import pandas as pd
import numpy as np
import time
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
from scapy.all import *
from collections import defaultdict
import logging

class DataProcessor:
    def __init__(self):
        self.scaler = MinMaxScaler()
        self.label_encoder = LabelEncoder()
        self.flow_stats = {}
        self.flow_timeout = 60  # Flow timeout in seconds
        self.feature_stats = defaultdict(dict)
        self.anomaly_thresholds = defaultdict(dict)
        
    def extract_features(self, packet):
        features = {
            'packet_size': len(packet),
            'protocol': packet.proto if 'proto' in packet else 0,
            'src_port': packet.sport if hasattr(packet, 'sport') else 0,
            'dst_port': packet.dport if hasattr(packet, 'dport') else 0,
            'flags': packet.flags if hasattr(packet, 'flags') else 0,
            'ttl': packet[IP].ttl if IP in packet else 0,
            'ip_len': packet[IP].len if IP in packet else 0,
            'ip_version': packet[IP].version if IP in packet else 0,
            'ip_frag': packet[IP].frag if IP in packet else 0,
            'ip_tos': packet[IP].tos if IP in packet else 0,
            'ip_id': packet[IP].id if IP in packet else 0,
            'ip_options': len(packet[IP].options) if IP in packet and hasattr(packet[IP], 'options') else 0,
            'ip_df': bool(packet[IP].flags & 2) if IP in packet else False,  # Don't Fragment flag
            'ip_mf': bool(packet[IP].flags & 1) if IP in packet else False,  # More Fragments flag
            'ip_offset': packet[IP].frag if IP in packet else 0,  # Fragment offset
            'ip_checksum': packet[IP].chksum if IP in packet else 0  # IP header checksum
        }  # <-- Added closing brace here
        
        # TCP specific features
        if TCP in packet:
            features.update({
                'tcp_window': packet[TCP].window,
                'tcp_flags': packet[TCP].flags,
                'tcp_seq': packet[TCP].seq,
                'tcp_ack': packet[TCP].ack,
                'tcp_dataofs': packet[TCP].dataofs,  # TCP data offset
                'tcp_reserved': packet[TCP].reserved,  # Reserved bits
                'tcp_urgptr': packet[TCP].urgptr,  # Urgent pointer
                'tcp_options_length': len(packet[TCP].options),  # Length of TCP options
                'tcp_syn_flag': bool(packet[TCP].flags & 0x02),  # SYN flag
                'tcp_fin_flag': bool(packet[TCP].flags & 0x01),  # FIN flag
                'tcp_rst_flag': bool(packet[TCP].flags & 0x04),  # RST flag
                'tcp_psh_flag': bool(packet[TCP].flags & 0x08),  # PSH flag
                'tcp_ack_flag': bool(packet[TCP].flags & 0x10),  # ACK flag
                'tcp_urg_flag': bool(packet[TCP].flags & 0x20)   # URG flag
            })
            
            # Add flow-based features
            flow_key = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            self.update_flow_stats(flow_key, packet)
            flow_features = self.get_flow_features(flow_key)
            features.update(flow_features)
        
        # UDP specific features
        if UDP in packet:
            features.update({
                'udp_len': packet[UDP].len
            })
            
        # Enhanced payload analysis
        if Raw in packet:
            try:
                payload = packet[Raw].load
                features.update({
                    'payload_entropy': self.calculate_entropy(payload),
                    'payload_size': len(payload),
                    'payload_word_count': len(str(payload).split()),
                    'has_http': b'HTTP' in payload or b'GET' in payload or b'POST' in payload,
                    'has_dns': packet.haslayer(DNS),
                    'has_ssl': packet.haslayer(TLS) or packet.haslayer(SSL)
                })
            except Exception as e:
                logging.warning(f"Error processing payload: {str(e)}")
                features.update({
                    'payload_entropy': 0.0,
                    'payload_size': 0,
                    'payload_word_count': 0,
                    'has_http': False,
                    'has_dns': False,
                    'has_ssl': False
                })
        
        # Add ICMP features if present
        if ICMP in packet:
            features.update({
                'icmp_type': packet[ICMP].type,
                'icmp_code': packet[ICMP].code,
                'icmp_seq': packet[ICMP].seq if hasattr(packet[ICMP], 'seq') else 0
            })
        
        # Add ARP features if present
        if ARP in packet:
            features.update({
                'arp_op': packet[ARP].op,
                'is_arp_request': packet[ARP].op == 1,
                'is_arp_reply': packet[ARP].op == 2
            })
            
        return features
        
    def calculate_entropy(self, payload):
        """Calculate Shannon entropy of packet payload"""
        if not payload:
            return 0.0
        prob = [float(payload.count(c)) / len(payload) for c in set(payload)]
        entropy = -sum([p * np.log2(p) for p in prob])
        return entropy
        
    def update_flow_stats(self, flow_key, packet):
        """Update flow statistics for a given flow"""
        current_time = float(packet.time) if hasattr(packet, 'time') else time.time()
        
        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                'start_time': current_time,
                'last_time': current_time,
                'packet_count': 0,
                'byte_count': 0,
                'packet_sizes': [],
                'inter_arrival_times': []
            }
        
        flow = self.flow_stats[flow_key]
        
        # Update packet count and byte count
        flow['packet_count'] += 1
        flow['byte_count'] += len(packet)
        
        # Update packet sizes list
        flow['packet_sizes'].append(len(packet))
        
        # Calculate and update inter-arrival time
        if flow['packet_count'] > 1:
            inter_arrival = current_time - flow['last_time']
            flow['inter_arrival_times'].append(inter_arrival)
        
        flow['last_time'] = current_time
        
        # Remove old flows
        self.cleanup_old_flows(current_time)
    
    def get_flow_features(self, flow_key):
        """Extract statistical features from flow data"""
        if flow_key not in self.flow_stats:
            return {}
            
        flow = self.flow_stats[flow_key]
        features = {
            'flow_duration': flow['last_time'] - flow['start_time'],
            'flow_packets': flow['packet_count'],
            'flow_bytes': flow['byte_count'],
            'flow_rate': flow['packet_count'] / (flow['last_time'] - flow['start_time'] + 1e-6),
            'flow_avg_size': np.mean(flow['packet_sizes']) if flow['packet_sizes'] else 0,
            'flow_std_size': np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        }
        
        # Add inter-arrival time statistics if available
        if flow['inter_arrival_times']:
            features.update({
                'flow_iat_mean': np.mean(flow['inter_arrival_times']),
                'flow_iat_std': np.std(flow['inter_arrival_times']) if len(flow['inter_arrival_times']) > 1 else 0,
                'flow_iat_max': max(flow['inter_arrival_times']),
                'flow_iat_min': min(flow['inter_arrival_times'])
            })
            
        return features
    
    def cleanup_old_flows(self, current_time):
        """Remove flows that have exceeded the timeout period"""
        expired_flows = []
        for flow_key, flow in self.flow_stats.items():
            if current_time - flow['last_time'] > self.flow_timeout:
                expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            del self.flow_stats[flow_key]
        
    def preprocess_data(self, df):
        # Fill missing values with appropriate defaults
        df = df.fillna({
            'packet_size': 0,
            'src_port': 0,
            'dst_port': 0,
            'ttl': 64,  # Common default TTL
            'ip_len': 0,
            'tcp_window': 0,
            'tcp_seq': 0,
            'tcp_ack': 0,
            'udp_len': 0,
            'payload_entropy': 0,
            'ip_frag': 0,
            'ip_tos': 0,
            'ip_id': 0,
            'ip_options': 0
        })
        
        # Identify numeric features
        numeric_features = [
            'packet_size', 'src_port', 'dst_port', 'ttl', 'ip_len',
            'tcp_window', 'tcp_seq', 'tcp_ack', 'udp_len', 'payload_entropy',
            'ip_frag', 'ip_tos', 'ip_id', 'ip_options'
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
    
    def update_feature_statistics(self, features):
        """Update running statistics for numerical features"""
        for feature, value in features.items():
            if isinstance(value, (int, float)):
                stats = self.feature_stats[feature]
                stats['min'] = min(stats['min'], value)
                stats['max'] = max(stats['max'], value)
                stats['sum'] += value
                stats['count'] += 1
                
                # Calculate moving average and standard deviation
                if stats['count'] > 1:
                    mean = stats['sum'] / stats['count']
                    if 'variance_sum' not in stats:
                        stats['variance_sum'] = 0
                    stats['variance_sum'] += (value - mean) ** 2
                    stats['std'] = math.sqrt(stats['variance_sum'] / (stats['count'] - 1))
                    
                    # Update anomaly thresholds
                    if stats['count'] > 30:  # Enough samples for statistical significance
                        self.anomaly_thresholds[feature] = {
                            'lower': mean - 3 * stats['std'],
                            'upper': mean + 3 * stats['std']
                        }