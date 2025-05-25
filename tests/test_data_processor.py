import unittest
import pandas as pd
import numpy as np
from data_processor import DataProcessor # Assumes data_processor.py is in root or PYTHONPATH
from scapy.all import IP, TCP, UDP, ICMP, Raw # Specific Scapy imports

class TestDataProcessor(unittest.TestCase):

    def setUp(self):
        self.processor = DataProcessor()
        # Sample packets
        self.tcp_packet = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags='S') / Raw(load="payload")
        self.udp_packet = IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=1000, dport=53) / Raw(load="udp_payload")
        self.icmp_packet = IP(src="1.2.3.4", dst="5.6.7.8") / ICMP()
        self.ip_packet = IP(src="10.0.0.1", dst="10.0.0.2", proto=50) # ESP packet, no L4 payload for Scapy by default
        self.packet_no_payload = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags='A')
        self.packet_simple_payload = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags='PA') / Raw(load=b"AAAAA")
        self.packet_complex_payload = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags='F') / Raw(load=b"abcde123")

    def test_extract_features_completeness(self):
        packets_to_test = [self.tcp_packet, self.udp_packet, self.icmp_packet, self.ip_packet]
        for packet in packets_to_test:
            with self.subTest(packet_type=packet.summary()):
                features = self.processor.extract_features(packet)
                self.assertEqual(set(features.keys()), set(self.processor.ALL_FEATURE_NAMES), 
                                 f"Feature keys mismatch for {packet.summary()}")

    def test_extract_features_values(self):
        # TCP Packet
        tcp_features = self.processor.extract_features(self.tcp_packet)
        self.assertEqual(tcp_features['packet_size'], len(self.tcp_packet))
        self.assertEqual(tcp_features['protocol'], 6) # TCP
        self.assertEqual(tcp_features['src_port'], 1234)
        self.assertEqual(tcp_features['dst_port'], 80)
        self.assertTrue(isinstance(tcp_features['tcp_flags'], int))

        # UDP Packet
        udp_features = self.processor.extract_features(self.udp_packet)
        self.assertEqual(udp_features['protocol'], 17) # UDP
        self.assertEqual(udp_features['src_port'], 1000)
        self.assertEqual(udp_features['dst_port'], 53)
        self.assertTrue(udp_features['udp_len'] > 0)

        # IP Packet (no specific L4 for these features)
        ip_features = self.processor.extract_features(self.ip_packet)
        self.assertEqual(ip_features['protocol'], 50) # ESP
        self.assertEqual(ip_features['tcp_window'], 0) # Default for non-TCP
        self.assertEqual(ip_features['udp_len'], 0) # Default for non-UDP
        self.assertEqual(ip_features['src_port'], 0) # Default if not TCP/UDP

    def test_payload_entropy(self):
        # No payload
        features_no_payload = self.processor.extract_features(self.packet_no_payload)
        self.assertEqual(features_no_payload['payload_entropy'], 0.0)

        # Simple payload (zero entropy)
        features_simple_payload = self.processor.extract_features(self.packet_simple_payload)
        self.assertEqual(features_simple_payload['payload_entropy'], 0.0)

        # Complex payload (non-zero entropy)
        features_complex_payload = self.processor.extract_features(self.packet_complex_payload)
        self.assertTrue(features_complex_payload['payload_entropy'] > 0)

    def test_preprocess_data_structure(self):
        feature_dicts = [
            self.processor.extract_features(self.tcp_packet),
            self.processor.extract_features(self.udp_packet)
        ]
        df = pd.DataFrame(feature_dicts)
        processed_df = self.processor.preprocess_data(df.copy())
        
        self.assertEqual(list(processed_df.columns), self.processor.ALL_FEATURE_NAMES)
        self.assertEqual(processed_df.shape[1], len(self.processor.ALL_FEATURE_NAMES))
        self.assertFalse(processed_df.isnull().values.any())

    def test_preprocess_data_scaling_encoding(self):
        # Construct more diverse data for better testing of scaling/encoding
        row1 = {key: 0 for key in self.processor.ALL_FEATURE_NAMES}
        row1.update({
            'packet_size': 100, 'protocol': 6, 'src_port': 1000, 'ip_version': 4,
            'dst_port': 80, 'ttl': 64, 'ip_len': 100, 'tcp_window': 1024, 'tcp_flags': 2, # SYN flag
            'payload_entropy': 1.5
        })
        
        row2 = {key: 0 for key in self.processor.ALL_FEATURE_NAMES}
        row2.update({
            'packet_size': 50, 'protocol': 17, 'src_port': 2000, 'ip_version': 4,
            'dst_port': 53, 'ttl': 128, 'ip_len': 50, 'udp_len': 30,
            'payload_entropy': 0.5
        })
        
        row3 = {key: 0 for key in self.processor.ALL_FEATURE_NAMES} # Test default/zero values
        row3.update({'packet_size': 20, 'protocol': 1, 'ip_version': 4, 'flags': 0, 'payload_entropy': 0.0})

        df = pd.DataFrame([row1, row2, row3])
        # Ensure all columns from ALL_FEATURE_NAMES are present, fill missing with 0 if any
        df = df.reindex(columns=self.processor.ALL_FEATURE_NAMES, fill_value=0)

        processed_df = self.processor.preprocess_data(df.copy())

        for numeric_col in self.processor.NUMERIC_FEATURES:
            if df[numeric_col].nunique() > 1: # Only test scaling if there's variance
                self.assertTrue((processed_df[numeric_col] >= 0).all() and (processed_df[numeric_col] <= 1).all(),
                                f"Numeric feature {numeric_col} not scaled between 0 and 1.")
            elif df[numeric_col].nunique() == 1 and df[numeric_col].iloc[0] != 0:
                 # If constant non-zero, scaled should be 0 (MinMaxScaler behavior with single value)
                 # Or it could be 1 if that value was the max and min. Simpler: it should be constant.
                 self.assertTrue(np.allclose(processed_df[numeric_col], 0.0) or np.allclose(processed_df[numeric_col], 1.0) or processed_df[numeric_col].nunique() == 1,
                                 f"Numeric feature {numeric_col} with single value not scaled correctly.")
            else: # all zeros
                self.assertTrue((processed_df[numeric_col] == 0).all(),
                                f"Numeric feature {numeric_col} (all zeros) changed after scaling.")

        for cat_col in self.processor.CATEGORICAL_FEATURES:
            self.assertTrue(pd.api.types.is_integer_dtype(processed_df[cat_col]),
                            f"Categorical feature {cat_col} not encoded to integer.")

    def test_apply_smote_basic(self):
        # Create sample imbalanced data
        num_majority = 20
        num_minority = 2
        X_dict_list = []
        for i in range(num_majority + num_minority):
            sample = {key: 0 for key in self.processor.ALL_FEATURE_NAMES}
            sample.update({
                'packet_size': np.random.randint(50, 150),
                'protocol': 6 if i < num_majority + num_minority / 2 else 17, # some variation
                'src_port': np.random.randint(1000, 2000),
                'ip_version': 4,
                'payload_entropy': np.random.rand() * 5
            })
            X_dict_list.append(sample)
        
        X_df = pd.DataFrame(X_dict_list)
        X_df = X_df.reindex(columns=self.processor.ALL_FEATURE_NAMES, fill_value=0)
        # Preprocess before SMOTE as it's done in train_model.py
        X_df_processed = self.processor.preprocess_data(X_df.copy())

        y_list = [0]*num_majority + [1]*num_minority
        y_series = pd.Series(y_list)

        # Check if there are at least two classes for SMOTE
        if y_series.nunique() < 2:
            self.skipTest("Skipping SMOTE test as there are less than 2 classes in generated data.")
            return

        X_resampled_df, y_resampled_series = self.processor.apply_smote(X_df_processed.copy(), y_series.copy())
        
        self.assertTrue(len(X_resampled_df) > len(X_df_processed), "SMOTE should increase sample size.")
        # SMOTE aims to balance classes, so counts should be equal
        resampled_counts = y_resampled_series.value_counts()
        self.assertEqual(resampled_counts[0], resampled_counts[1], "SMOTE should balance class counts.")

if __name__ == '__main__':
    unittest.main()
