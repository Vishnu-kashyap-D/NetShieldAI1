// TypeScript mirror of backend/app/feature_glossary.py -- same 76 real CICIDS2017/CICFlowMeter
// feature names and definitions. Duplicated (not imported) because MockDataProvider makes no
// network calls at all, by design (see mockProvider.ts) -- mock mode's chatbot needs this data
// available entirely client-side. Keep the two files' text in sync when either changes.
export const FEATURE_GLOSSARY: Record<string, string> = {
  "Flow Duration": "Total duration of the flow, in microseconds, from the first packet to the last.",
  "Total Fwd Packets": "Total number of packets sent in the forward direction (client to server) during the flow.",
  "Total Backward Packets": "Total number of packets sent in the backward direction (server to client) during the flow.",
  "Total Length of Fwd Packets": "Sum of the sizes (in bytes) of all forward-direction packets in the flow.",
  "Total Length of Bwd Packets": "Sum of the sizes (in bytes) of all backward-direction packets in the flow.",
  "Fwd Packet Length Max": "Largest single forward-direction packet size (bytes) observed in the flow.",
  "Fwd Packet Length Min": "Smallest single forward-direction packet size (bytes) observed in the flow.",
  "Fwd Packet Length Mean": "Average forward-direction packet size (bytes) across the flow.",
  "Fwd Packet Length Std": "Standard deviation of forward-direction packet sizes (bytes) -- how variable packet sizes were.",
  "Bwd Packet Length Max": "Largest single backward-direction packet size (bytes) observed in the flow.",
  "Bwd Packet Length Min": "Smallest single backward-direction packet size (bytes) observed in the flow.",
  "Bwd Packet Length Mean": "Average backward-direction packet size (bytes) across the flow.",
  "Bwd Packet Length Std": "Standard deviation of backward-direction packet sizes (bytes).",
  "Flow Bytes/s": "Average data rate of the flow -- total bytes transferred divided by flow duration.",
  "Flow Packets/s": "Average packet rate of the flow -- total packets transferred divided by flow duration.",
  "Flow IAT Mean": "Mean inter-arrival time (gap) between consecutive packets in the flow, in either direction.",
  "Flow IAT Std": "Standard deviation of inter-arrival times between consecutive packets in the flow.",
  "Flow IAT Max": "Longest gap observed between two consecutive packets in the flow.",
  "Flow IAT Min": "Shortest gap observed between two consecutive packets in the flow.",
  "Fwd IAT Total": "Sum of all inter-arrival times between consecutive forward-direction packets.",
  "Fwd IAT Mean": "Mean inter-arrival time between consecutive forward-direction packets.",
  "Fwd IAT Std": "Standard deviation of inter-arrival times between consecutive forward-direction packets.",
  "Fwd IAT Max": "Longest gap between two consecutive forward-direction packets.",
  "Fwd IAT Min": "Shortest gap between two consecutive forward-direction packets.",
  "Bwd IAT Total": "Sum of all inter-arrival times between consecutive backward-direction packets.",
  "Bwd IAT Mean": "Mean inter-arrival time between consecutive backward-direction packets.",
  "Bwd IAT Std": "Standard deviation of inter-arrival times between consecutive backward-direction packets.",
  "Bwd IAT Max": "Longest gap between two consecutive backward-direction packets.",
  "Bwd IAT Min": "Shortest gap between two consecutive backward-direction packets.",
  "Fwd PSH Flags": "Count of forward-direction packets with the TCP PSH flag set (push buffered data to the application).",
  "Bwd PSH Flags": "Count of backward-direction packets with the TCP PSH flag set.",
  "Fwd URG Flags": "Count of forward-direction packets with the TCP URG flag set (urgent data).",
  "Bwd URG Flags": "Count of backward-direction packets with the TCP URG flag set.",
  "Fwd Header Length": "Total bytes used by headers across all forward-direction packets in the flow.",
  "Bwd Header Length": "Total bytes used by headers across all backward-direction packets in the flow.",
  "Fwd Packets/s": "Forward-direction packet rate -- forward packets divided by flow duration.",
  "Bwd Packets/s": "Backward-direction packet rate -- backward packets divided by flow duration.",
  "Min Packet Length": "Smallest packet size (bytes) observed in the flow, either direction.",
  "Max Packet Length": "Largest packet size (bytes) observed in the flow, either direction.",
  "Packet Length Mean": "Average packet size (bytes) across the whole flow, either direction.",
  "Packet Length Std": "Standard deviation of packet sizes (bytes) across the whole flow.",
  "Packet Length Variance": "Variance of packet sizes (bytes) across the whole flow -- the squared version of Packet Length Std.",
  "FIN Flag Count": "Count of packets with the TCP FIN flag set (graceful connection close).",
  "SYN Flag Count": "Count of packets with the TCP SYN flag set (connection initiation) -- often elevated in scans/floods.",
  "RST Flag Count": "Count of packets with the TCP RST flag set (abrupt connection reset).",
  "PSH Flag Count": "Count of packets with the TCP PSH flag set, either direction.",
  "ACK Flag Count": "Count of packets with the TCP ACK flag set (acknowledgment).",
  "URG Flag Count": "Count of packets with the TCP URG flag set, either direction.",
  "CWE Flag Count": "Count of packets with the TCP CWE (Congestion Window Reduced) flag set.",
  "ECE Flag Count": "Count of packets with the TCP ECE (ECN-Echo) flag set.",
  "Down/Up Ratio": "Ratio of backward (download) packets to forward (upload) packets in the flow.",
  "Average Packet Size": "Mean packet size (bytes) across the flow, computed from total bytes over total packets.",
  "Avg Fwd Segment Size": "Average TCP segment size (bytes) for forward-direction packets.",
  "Avg Bwd Segment Size": "Average TCP segment size (bytes) for backward-direction packets.",
  "Fwd Avg Bytes/Bulk": "Average bytes per bulk transfer in the forward direction (a 'bulk' is a burst of packets sent back-to-back).",
  "Fwd Avg Packets/Bulk": "Average number of packets per bulk transfer in the forward direction.",
  "Fwd Avg Bulk Rate": "Average data rate (bytes/s) of forward-direction bulk transfers.",
  "Bwd Avg Bytes/Bulk": "Average bytes per bulk transfer in the backward direction.",
  "Bwd Avg Packets/Bulk": "Average number of packets per bulk transfer in the backward direction.",
  "Bwd Avg Bulk Rate": "Average data rate (bytes/s) of backward-direction bulk transfers.",
  "Subflow Fwd Packets": "Average number of forward-direction packets per subflow (a flow segmented into smaller chunks).",
  "Subflow Fwd Bytes": "Average number of forward-direction bytes per subflow.",
  "Subflow Bwd Packets": "Average number of backward-direction packets per subflow.",
  "Subflow Bwd Bytes": "Average number of backward-direction bytes per subflow.",
  Init_Win_bytes_forward: "TCP initial window size (bytes) advertised by the flow's originator.",
  Init_Win_bytes_backward: "TCP initial window size (bytes) advertised by the flow's responder.",
  act_data_pkt_fwd:
    "Count of forward-direction packets that carried at least 1 byte of TCP payload (i.e. actual data, not just control packets).",
  min_seg_size_forward: "Smallest TCP segment size (bytes) observed in the forward direction.",
  "Active Mean": "Mean duration of periods the flow was actively transferring data before going idle.",
  "Active Std": "Standard deviation of the flow's active-period durations.",
  "Active Max": "Longest single active-period duration observed in the flow.",
  "Active Min": "Shortest single active-period duration observed in the flow.",
  "Idle Mean": "Mean duration of periods the flow was idle (no data transfer) before becoming active again.",
  "Idle Std": "Standard deviation of the flow's idle-period durations.",
  "Idle Max": "Longest single idle-period duration observed in the flow.",
  "Idle Min": "Shortest single idle-period duration observed in the flow.",
};

const NAMES_BY_LENGTH = Object.keys(FEATURE_GLOSSARY).sort((a, b) => b.length - a.length);

/** Real feature names that appear (case-insensitively) in free text, longest match first. */
export function findFeaturesMentioned(text: string): string[] {
  const lowered = text.toLowerCase();
  const found: string[] = [];
  for (const name of NAMES_BY_LENGTH) {
    const escaped = name.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`(?<![a-zA-Z0-9_./])${escaped}(?![a-zA-Z0-9_])`);
    if (pattern.test(lowered)) found.push(name);
  }
  return found;
}
