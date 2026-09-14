"""Converts a captured pcap into flow-feature CSV and feeds it into the NetShield AI backend.

This is the "real traffic, not a dataset" counterpart to stream_simulator.py (which replays a
static CSV). The capture itself happens on the isolated lab's victim VM (`tcpdump -i <iface> -w
capture.pcap`, see the live-testing build plan); copy the resulting pcap out to this machine
(`scp victim@<victim-ip>:~/capture.pcap .`) and point this script at it.

Originally this called the Java CICFlowMeter CLI (`cfm`) directly. That doesn't work offline: it's
not installed on either lab VM (no internet there to install it, no Java toolchain either), and
building it from source needs a full Maven + jnetpcap toolchain. Converting instead runs here, on
the host, using the `cicflowmeter` PyPI package (a pure-Python port) -- `pip install cicflowmeter`.

That package has three real bugs against modern scapy/numpy, all worked around below:
  1. Its AsyncSniffer-based CLI never flushes accumulated flows to CSV for an offline pcap with
     store=False -- the flush only happens as a side effect of session.toPacketList(), which
     nothing calls in that code path. Worked around by driving the session directly (PcapReader
     + on_packet_received loop) instead of going through its sniffer.py/AsyncSniffer wrapper.
  2. get_statistics() runs numpy.mean/var directly on scapy's EDecimal timestamps, which modern
     numpy can't convert (TypeError: conversion from numpy.int64 to Decimal). Worked around by
     converting each packet's timestamp to a plain float at read time.
  3. Three Flow methods (add_packet, update_subflow, update_active_idle) multiply/divide by
     Decimal("1e6") against those now-float timestamps, which Python doesn't support mixing
     (TypeError: unsupported operand type(s) for */: 'float' and 'decimal.Decimal'). Worked
     around by monkeypatching those three methods to use a plain 1e6 float literal instead,
     matching how the rest of the file already does it (see flow.py line ~102).

It also has a fourth bug, worse than the first three because it doesn't crash -- it just silently
produces wrong numbers: FlagCount.has_flag() checks `packet.flags`, which scapy resolves to the
*IP layer's* flags field (fragmentation bits: DF/MF), not TCP's SYN/ACK/RST/etc. -- both layers
have a field literally named "flags", and attribute lookup on the outer packet finds IP's first.
`str(packet.flags)` for a typical packet is "DF", and "F" in "DF" happens to be True, so FIN Flag
Count comes out populated (looking plausible) purely by coincidence, while SYN/ACK/RST/PSH/URG/
ECE Flag Count are always 0 for every flow, benign or attack alike. Worked around by checking
`packet["TCP"].flags` explicitly instead.

Its output columns are also a different (abbreviated snake_case) naming convention than the
Flow Duration / Total Fwd Packets / ... schema artifacts/preprocessing.joblib was trained on --
verified below to be a complete 1:1 rename, no unmapped trained features, no CICFlowMeter-version
column drift to worry about.

Usage:
    python backend/scripts/live_capture_feed.py capture.pcap
    python backend/scripts/live_capture_feed.py capture.pcap --source-name portscan_run1.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
from scapy.utils import PcapReader

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stream_simulator import _check_backend_ready, _login, _send_chunk  # noqa: E402

# cicflowmeter's snake_case output columns -> the exact 76 names
# artifacts/preprocessing.joblib was trained on (classic CICFlowMeter/CICIDS2017 schema).
RENAME = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwe_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}
TRAINED_76 = set(RENAME.values())


def _patch_cicflowmeter() -> None:
    """Apply the three workarounds described in the module docstring."""
    import numpy
    import cicflowmeter.flow as cf_flow
    from cicflowmeter.constants import ACTIVE_TIMEOUT, CLUMP_TIMEOUT
    from cicflowmeter.features.flag_count import FlagCount

    def _has_flag(self, flag, packet_direction=None):
        packets = (
            (p for p, d in self.feature.packets if d == packet_direction)
            if packet_direction is not None
            else (p for p, _ in self.feature.packets)
        )
        for packet in packets:
            if "TCP" in packet and flag[0] in str(packet["TCP"].flags):
                return 1
        return 0

    FlagCount.has_flag = _has_flag

    def _get_statistics(alist: list):
        iat = dict()
        if len(alist) > 1:
            floats = [float(x) for x in alist]
            iat["total"] = sum(floats)
            iat["max"] = max(floats)
            iat["min"] = min(floats)
            iat["mean"] = numpy.mean(floats)
            iat["std"] = numpy.sqrt(numpy.var(floats))
        else:
            iat = {"total": 0, "max": 0, "min": 0, "mean": 0, "std": 0}
        return iat

    def _add_packet(self, packet, direction):
        self.packets.append((packet, direction))
        self.update_flow_bulk(packet, direction)
        self.update_subflow(packet)
        if self.start_timestamp != 0:
            self.flow_interarrival_time.append(1e6 * (packet.time - self.latest_timestamp))
        self.latest_timestamp = max([packet.time, self.latest_timestamp])
        if "TCP" in packet:
            if direction == cf_flow.PacketDirection.FORWARD and self.init_window_size[direction] == 0:
                self.init_window_size[direction] = packet["TCP"].window
            elif direction == cf_flow.PacketDirection.REVERSE:
                self.init_window_size[direction] = packet["TCP"].window
        if self.start_timestamp == 0:
            self.start_timestamp = packet.time
            self.protocol = packet.proto

    def _update_subflow(self, packet):
        last_timestamp = self.latest_timestamp if self.latest_timestamp != 0 else packet.time
        if (packet.time - (last_timestamp / 1e6)) > CLUMP_TIMEOUT:
            self.update_active_idle(packet.time - last_timestamp)

    def _update_active_idle(self, current_time):
        if (current_time - self.last_active) > ACTIVE_TIMEOUT:
            duration = abs(float(self.last_active - self.start_active))
            if duration > 0:
                self.active.append(1e6 * duration)
            self.idle.append(1e6 * (current_time - self.last_active))
            self.start_active = current_time
            self.last_active = current_time
        else:
            self.last_active = current_time

    cf_flow.get_statistics = _get_statistics
    cf_flow.Flow.add_packet = _add_packet
    cf_flow.Flow.update_subflow = _update_subflow
    cf_flow.Flow.update_active_idle = _update_active_idle


def pcap_to_flow_csv(pcap_path: Path, out_csv: Path) -> pd.DataFrame:
    """Convert a captured pcap to a DataFrame in the model's trained column schema."""
    _patch_cicflowmeter()
    from cicflowmeter.flow_session import generate_session_class

    NewFlowSession = generate_session_class("flow", str(out_csv), None)
    session = NewFlowSession()

    count = 0
    with PcapReader(str(pcap_path)) as pcap_reader:
        for pkt in pcap_reader:
            pkt.time = float(pkt.time)
            session.on_packet_received(pkt)
            count += 1
    print(f"Read {count} packets from {pcap_path.name}.")

    # A handful of flows can still be open (never "matured") when the pcap ends -- flush them.
    # session.toPacketList() itself is broken (calls a super() method DefaultSession doesn't
    # have), so replicate just the flush half of it directly instead of calling that method.
    session.garbage_collect(None)

    df = pd.read_csv(out_csv, low_memory=False)
    df = df.rename(columns=RENAME)
    missing = TRAINED_76 - set(df.columns)
    if missing:
        print(f"WARNING: {len(missing)} trained columns missing after rename: {sorted(missing)}")
    df.to_csv(out_csv, index=False)
    print(f"{len(df)} flow rows -> {out_csv}")
    return df


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcap", help="Captured pcap file (copied from the victim VM).")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="Base URL of the running backend.")
    parser.add_argument("--source-name", default=None, help="Name to record as the alert source (default: the pcap's filename).")
    parser.add_argument(
        "--include-all-windows", dest="include_all_windows", action="store_true", default=True,
        help="Store Low-risk windows too (default: on).",
    )
    parser.add_argument("--alerts-only", dest="include_all_windows", action="store_false", help="Store only Medium/High windows.")
    parser.add_argument("--shap", action="store_true", default=True, help="Attach SHAP explanations (default: on).")
    parser.add_argument("--no-shap", dest="shap", action="store_false")
    parser.add_argument(
        "--email", default="hunter@netshield.ai",
        help="Account to log in as (POST /api/ingest/* requires Threat Hunter or Administrator).",
    )
    parser.add_argument("--password", default="NetShield@123", help="Password for --email.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise SystemExit(f"pcap not found: {pcap_path}")

    out_csv = pcap_path.with_suffix(".flows.csv")
    df = pcap_to_flow_csv(pcap_path, out_csv)
    if len(df) < 10:
        raise SystemExit(f"Only {len(df)} flow rows -- too few to form a detection window (needs >= 10).")

    session = __import__("requests").Session()
    _check_backend_ready(session, args.api_url)
    _login(session, args.api_url, args.email, args.password)

    source_name = args.source_name or pcap_path.with_suffix(".csv").name
    summary = _send_chunk(session, args.api_url, source_name, df, args.include_all_windows, args.shap)
    print("Ingest summary:")
    print(f"  windows_scored: {summary['windows_scored']}")
    print(f"  alerts_written: {summary['alerts_written']} (duplicates_skipped: {summary['duplicates_skipped']})")
    print(f"  risk_level_counts: {summary['risk_level_counts']}")
    print(f"  predicted_label_counts: {summary['predicted_label_counts']}")


if __name__ == "__main__":
    main()
