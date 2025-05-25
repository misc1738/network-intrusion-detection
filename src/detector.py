from scapy.all import *
import numpy as np
import pandas as pd
from data_processor import DataProcessor
from model import IntrusionDetectionModel
from alert_system import AlertSystem
import logging
from datetime import datetime

class NetworkDetector:
    def __init__(self, model, threshold=0.9, smtp_config=None):
        self.model = model
        self.threshold = threshold
        self.data_processor = DataProcessor()
        self.alert_system = AlertSystem(smtp_config)
        self.setup_logging()
        self.packet_buffer = []
        self.buffer_size = 32  # Increased buffer size for better batch processing
        self.suspicious_ips = set()  # Track suspicious IPs
        self.alert_cooldown = 300  # Alert cooldown in seconds
        
    def setup_logging(self):
        logging.basicConfig(
            filename='logs/detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def packet_callback(self, packet):
        if IP in packet:
            self.packet_buffer.append(packet)
            
            if len(self.packet_buffer) >= self.buffer_size:
                self.analyze_packet_batch()
                
    def analyze_packet_batch(self):
        if not self.packet_buffer:
            return

        features_list = []
        timestamps = []
        for packet in self.packet_buffer:
            features = self.data_processor.extract_features(packet)
            features_list.append(features)
            timestamps.append(datetime.now())

        df = pd.DataFrame(features_list)
        processed_features = self.data_processor.preprocess_data(df)

        # Reshape for LSTM if needed
        if len(processed_features.shape) == 2:
            processed_features = processed_features.values.reshape(
                (processed_features.shape[0], 1, processed_features.shape[1])
            )

        predictions = self.model.predict(processed_features)
        
        # Analyze predictions and trigger alerts
        for i, (pred, packet, timestamp) in enumerate(zip(predictions, self.packet_buffer, timestamps)):
            if pred > self.threshold:
                src_ip = packet[IP].src if IP in packet else None
                if src_ip and self._should_alert(src_ip, timestamp):
                    self.handle_intrusion(packet, pred)
                    self.suspicious_ips.add(src_ip)

        self.packet_buffer = []  # Clear buffer after analysis
        
    def handle_intrusion(self, packet, confidence):
        src_ip = packet[IP].src if IP in packet else 'Unknown'
        dst_ip = packet[IP].dst if IP in packet else 'Unknown'
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Enhanced packet analysis
        protocol = packet[IP].proto if IP in packet else 'Unknown'
        protocol_name = self._get_protocol_name(protocol)
        
        alert_msg = (
            f"Potential intrusion detected\n"
            f"Source IP: {src_ip}\n"
            f"Destination IP: {dst_ip}\n"
            f"Protocol: {protocol_name}\n"
            f"Confidence: {confidence:.2f}\n"
            f"Timestamp: {timestamp}"
        )
        
        packet_info = {
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': protocol_name,
            'Length': len(packet),
            'Time': timestamp,
            'TTL': packet[IP].ttl if IP in packet else 'Unknown',
            'Flags': packet[TCP].flags if TCP in packet else 'N/A',
            'Window Size': packet[TCP].window if TCP in packet else 'N/A'
        }
        
        self.trigger_alert(alert_msg, packet_info)
                
    def _get_protocol_name(self, protocol):
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocol_map.get(protocol, f'Unknown ({protocol})')

    def _should_alert(self, src_ip, timestamp):
        """Implement alert throttling to prevent alert fatigue"""
        if src_ip not in self.suspicious_ips:
            return True

        current_time = timestamp
        for prev_alert in self.alert_history:
            if prev_alert['ip'] == src_ip:
                time_diff = (current_time - prev_alert['time']).total_seconds()
                if time_diff < self.alert_cooldown:
                    return False
        return True

    def start_detection(self):
        logging.info("Starting network detection...")
        try:
            sniff(prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            logging.info("Detection stopped by user")
        except Exception as e:
            logging.error(f"Detection error: {str(e)}")
            raise
        
    def trigger_alert(self, message, packet_info):
        self.alert_system.log_alert(message)
        self.alert_system.send_email_alert(
            subject="Network Intrusion Detected",
            message=message,
            packet_info=packet_info
        )