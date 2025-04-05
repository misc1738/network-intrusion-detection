import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
from scapy.all import *

class DataProcessor:
    def __init__(self):
        self.scaler = MinMaxScaler()
        self.label_encoder = LabelEncoder()
        
    def extract_features(self, packet):
        features = {
            'packet_size': len(packet),
            'protocol': packet.proto if 'proto' in packet else 0,
            'src_port': packet.sport if hasattr(packet, 'sport') else 0,
            'dst_port': packet.dport if hasattr(packet, 'dport') else 0,
            'flags': packet.flags if hasattr(packet, 'flags') else 0,
            'ttl': packet[IP].ttl if IP in packet else 0,
            'ip_len': packet[IP].len if IP in packet else 0,
            'ip_version': packet[IP].version if IP in packet else 0
        }
        
        # TCP specific features
        if TCP in packet:
            features.update({
                'tcp_window': packet[TCP].window,
                'tcp_flags': packet[TCP].flags,
                'tcp_seq': packet[TCP].seq,
                'tcp_ack': packet[TCP].ack
            })
        
        # UDP specific features
        if UDP in packet:
            features.update({
                'udp_len': packet[UDP].len
            })
            
        # Calculate entropy of payload if present
        if Raw in packet:
            payload = str(packet[Raw].load)
            features['payload_entropy'] = self.calculate_entropy(payload)
            
        return features
        
    def calculate_entropy(self, payload):
        """Calculate Shannon entropy of packet payload"""
        prob = [float(payload.count(c)) / len(payload) for c in set(payload)]
        entropy = -sum([p * np.log2(p) for p in prob])
        return entropy
        
    def preprocess_data(self, df):
        # Fill missing values
        df = df.fillna(0)
        
        # Identify numeric features
        numeric_features = [
            'packet_size', 'src_port', 'dst_port', 'ttl', 'ip_len',
            'tcp_window', 'tcp_seq', 'tcp_ack', 'udp_len', 'payload_entropy'
        ]
        
        # Remove features that don't exist in the dataframe
        numeric_features = [f for f in numeric_features if f in df.columns]
        
        # Normalize numeric features
        if numeric_features:
            df[numeric_features] = self.scaler.fit_transform(df[numeric_features])
        
        # Encode categorical features
        categorical_features = ['protocol', 'ip_version']
        categorical_features = [f for f in categorical_features if f in df.columns]
        
        for feature in categorical_features:
            df[feature] = self.label_encoder.fit_transform(df[feature].astype(str))
        
        # Handle class imbalance if this is training data
        if 'label' in df.columns and len(df) > 1:  # Only apply SMOTE if we have multiple samples
            try:
                smote = SMOTE(random_state=42)
                X = df.drop('label', axis=1)
                y = df['label']
                X_resampled, y_resampled = smote.fit_resample(X, y)
                return pd.concat([X_resampled, y_resampled], axis=1)
            except Exception as e:
                logging.warning(f"SMOTE resampling failed: {str(e)}. Proceeding with original data.")
                return df
        
        return df