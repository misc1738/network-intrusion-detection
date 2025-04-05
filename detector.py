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
        self.buffer_size = 10  # Number of packets to analyze together
        
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
        features_list = []
        for packet in self.packet_buffer:
            features = self.data_processor.extract_features(packet)
            features_list.append(features)
            
        if features_list:
            df = pd.DataFrame(features_list)
            processed_features = self.data_processor.preprocess_data(df)
            predictions = self.model.predict(processed_features)
            
            for i, (pred, packet) in enumerate(zip(predictions, self.packet_buffer)):
                if pred > self.threshold:
                    self.handle_intrusion(packet, pred)
                    
        self.packet_buffer = []  # Clear buffer after analysis
        
    def handle_intrusion(self, packet, confidence):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        alert_msg = f"Potential intrusion detected\nSource IP: {src_ip}\nDestination IP: {dst_ip}\nConfidence: {confidence:.2f}\nTimestamp: {timestamp}"
        
        packet_info = {
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': packet[IP].proto,
            'Length': len(packet),
            'Time': timestamp
        }
        
        self.trigger_alert(alert_msg, packet_info)
                
    def start_detection(self):
        logging.info("Starting network detection...")
        sniff(prn=self.packet_callback, store=0)
        
    def trigger_alert(self, message, packet_info):
        self.alert_system.log_alert(message)
        self.alert_system.send_email_alert(
            subject="Network Intrusion Detected",
            message=message,
            packet_info=packet_info
        )