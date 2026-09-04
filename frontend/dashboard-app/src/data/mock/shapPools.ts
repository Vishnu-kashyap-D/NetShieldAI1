import type { AttackCategory } from "../../types/api";

/**
 * Which raw features plausibly drive SHAP importance for each attack category,
 * loosely grounded in the Deep-Dive report's per-feature-group descriptions
 * (Chapter 1.2: rate/IAT features for floods, header/flag features for scans,
 * active/idle timing for beaconing, packet-size regularity for brute force).
 * Not real SHAP output -- there is no trained explainer running in mock mode.
 */
export const SHAP_FEATURE_POOLS: Record<Exclude<AttackCategory, "Normal">, readonly string[]> = {
  "DoS / DDoS": [
    "Flow Bytes/s",
    "Flow Packets/s",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "Idle Mean",
    "Active Mean",
    "Fwd IAT Mean",
    "Bwd Packet Length Std",
  ],
  "Port Scanning": [
    "Fwd Packets/s",
    "Init_Win_bytes_forward",
    "Flow Duration",
    "Bwd Packets/s",
    "Packet Length Variance",
    "Down/Up Ratio",
    "RST Flag Count",
    "Fwd Header Length",
  ],
  "Botnet Activity": [
    "Idle Mean",
    "Flow Duration",
    "Fwd Packet Length Mean",
    "Bwd IAT Mean",
    "Total Length of Fwd Packets",
    "Down/Up Ratio",
    "Active Mean",
    "Fwd Header Length",
  ],
  "Brute Force": [
    "Fwd IAT Mean",
    "Flow Duration",
    "Fwd Packet Length Std",
    "SYN Flag Count",
    "Active Mean",
    "Packet Length Std",
    "Fwd Packet Length Mean",
  ],
  "Malware Traffic": [
    "Packet Length Variance",
    "PSH Flag Count",
    "Bwd Packet Length Mean",
    "Flow Duration",
    "Fwd Packet Length Std",
    "Active Mean",
  ],
  "Data Exfiltration": ["Flow Duration", "Idle Mean", "Flow Bytes/s", "Bwd IAT Mean", "Active Mean"],
};
