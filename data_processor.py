import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
from scapy.all import IP, TCP, UDP, Raw # Specific imports
import logging # For logging SMOTE issues

class DataProcessor:
    ALL_FEATURE_NAMES = [
        'packet_size', 'protocol', 'src_port', 'dst_port', 'flags', 
        'ttl', 'ip_len', 'ip_version', 
        'tcp_window', 'tcp_flags', 'tcp_seq', 'tcp_ack', 
        'udp_len', 'payload_entropy'
    ]
    # Define which features are numeric and categorical based on ALL_FEATURE_NAMES
    NUMERIC_FEATURES = [
        'packet_size', 'src_port', 'dst_port', 'flags', # Assuming 'flags' is a numeric (e.g. int representation of bitmask)
        'ttl', 'ip_len', 
        'tcp_window', 'tcp_flags', # Assuming 'tcp_flags' is numeric
        'tcp_seq', 'tcp_ack', 'udp_len', 'payload_entropy'
    ]
    CATEGORICAL_FEATURES = [
        'protocol', 'ip_version'
    ]

    def __init__(self):
        self.scaler = MinMaxScaler()
        self.label_encoders = {col: LabelEncoder() for col in self.CATEGORICAL_FEATURES}
        # Ensure no feature is in both lists (developer check)
        assert len(set(self.NUMERIC_FEATURES) & set(self.CATEGORICAL_FEATURES)) == 0
        # Ensure all features are covered (developer check)
        assert set(self.NUMERIC_FEATURES) | set(self.CATEGORICAL_FEATURES) == set(self.ALL_FEATURE_NAMES)
        
    def extract_features(self, packet):
        # Initialize all features with a default value (0)
        features = {key: 0 for key in self.ALL_FEATURE_NAMES}

        features['packet_size'] = len(packet)
        # Scapy's packet.proto is often an int (e.g., 6 for TCP, 17 for UDP)
        # It can be used directly or mapped to names if preferred for encoding.
        # For now, using it as a direct categorical number.
        if IP in packet: # Check if it's an IP packet first
            features['protocol'] = packet[IP].proto
            features['ttl'] = packet[IP].ttl
            features['ip_len'] = packet[IP].len
            features['ip_version'] = packet[IP].version
            features['flags'] = int(packet[IP].flags) # Ensure IP flags are integer

        if hasattr(packet, 'sport'): # More general check for source port
            features['src_port'] = packet.sport
        if hasattr(packet, 'dport'): # More general check for destination port
            features['dst_port'] = packet.dport
        
        # TCP specific features
        if TCP in packet:
            features['tcp_window'] = packet[TCP].window
            features['tcp_flags'] = int(packet[TCP].flags) # Ensure TCP flags are integer
            features['tcp_seq'] = packet[TCP].seq
            features['tcp_ack'] = packet[TCP].ack
        
        # UDP specific features
        if UDP in packet:
            features['udp_len'] = packet[UDP].len
            
        # Calculate entropy of payload if present
        if Raw in packet and packet[Raw].load:
            payload = bytes(packet[Raw].load) # Ensure payload is bytes for consistent entropy calc
            features['payload_entropy'] = self.calculate_entropy(payload)
            
        return features
        
    def calculate_entropy(self, payload_bytes):
        """Calculate Shannon entropy of packet payload (bytes)."""
        if not payload_bytes: # Handle empty payload
            return 0.0
        
        byte_counts = np.bincount(np.frombuffer(payload_bytes, dtype=np.uint8), minlength=256)
        probabilities = byte_counts[byte_counts > 0] / len(payload_bytes)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
        
    def preprocess_data(self, df):
        # Fill missing values (e.g., for packets that are not IP, or don't have TCP/UDP)
        # This should ideally be handled by the default values in extract_features,
        # but an explicit fillna can catch any other NaNs.
        df = df.fillna(0)

        # Ensure all defined columns are present and in correct order
        df = df.reindex(columns=self.ALL_FEATURE_NAMES, fill_value=0)
        
        # Normalize numeric features
        # Filter NUMERIC_FEATURES to only those present in df columns to avoid KeyErrors if df is partial
        # Though reindex should ensure all ALL_FEATURE_NAMES are present.
        current_numeric_features = [f for f in self.NUMERIC_FEATURES if f in df.columns]
        if current_numeric_features:
            df[current_numeric_features] = self.scaler.fit_transform(df[current_numeric_features])
        
        # Encode categorical features
        current_categorical_features = [f for f in self.CATEGORICAL_FEATURES if f in df.columns]
        for feature in current_categorical_features:
            df[feature] = self.label_encoders[feature].fit_transform(df[feature].astype(str))
        
        return df

    def apply_smote(self, X_df, y_series):
        """Applies SMOTE to handle class imbalance."""
        # Ensure X_df columns are in the canonical order before SMOTE
        X_df = X_df.reindex(columns=self.ALL_FEATURE_NAMES, fill_value=0)
        try:
            smote = SMOTE(random_state=42)
            X_resampled, y_resampled = smote.fit_resample(X_df, y_series)
            # SMOTE returns numpy arrays, convert X_resampled back to DataFrame with correct columns
            return pd.DataFrame(X_resampled, columns=self.ALL_FEATURE_NAMES), y_resampled
        except Exception as e:
            logging.warning(f"SMOTE resampling failed: {str(e)}. Proceeding with original data.")
            return X_df, y_series
