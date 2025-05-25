# Placeholder for the actual generated code for detector.py
# The real code would include the new process_pcap_file method
# and any related adjustments.

from scapy.all import IP, sniff, rdpcap # Added rdpcap
import numpy as np
import pandas as pd
from data_processor import DataProcessor
from model import IntrusionDetectionModel
from alert_system import AlertSystem
import logging
import sys 
from datetime import datetime
import configparser
import os

class NetworkDetector:
    def __init__(self, ids_model_instance):
        self.ids_model = ids_model_instance
        self.data_processor = DataProcessor()
        self.alert_system = AlertSystem()
        
        config = configparser.ConfigParser()
        config.read('config.ini')
        
        self.threshold = config['Model'].getfloat('threshold', 0.9)
        self.timesteps = config['Model'].getint('timesteps', 10)
        self.num_features = config['Model'].getint('features', 14)
        self.config = config
        
        self.buffer_size = self.timesteps
        self.packet_buffer_raw = []
        
        self.setup_logging()
        
    def setup_logging(self):
        log_file_path = self.config['Paths'].get('detection_log_file', 'logs/detection.log')
        log_dir = os.path.dirname(log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        self.logger = logging.getLogger('NetworkDetector')
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            file_handler = logging.FileHandler(log_file_path)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.INFO)
            self.logger.addHandler(file_handler)

            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            console_handler.setLevel(logging.INFO)
            self.logger.addHandler(console_handler)
            
            self.logger.propagate = False
        
    def packet_callback(self, packet):
        if IP in packet:
            self.packet_buffer_raw.append(packet)
            
            if len(self.packet_buffer_raw) >= self.buffer_size:
                self.analyze_packet_batch(is_final_batch=False)
                self.packet_buffer_raw = [] 
                
    def analyze_packet_batch(self, is_final_batch=False): # Added is_final_batch
        # For LSTM, we need a full sequence of 'timesteps' length.
        # If it's the final batch from a PCAP and it's smaller than timesteps, we cannot process it with the current LSTM setup.
        if not self.packet_buffer_raw or len(self.packet_buffer_raw) < self.timesteps and is_final_batch:
            if is_final_batch and self.packet_buffer_raw:
                self.logger.info(f"Final batch has {len(self.packet_buffer_raw)} packets, less than {self.timesteps} timesteps. Skipping analysis for this partial sequence.")
            return
        
        # If it's not a final batch, it must be full due to packet_callback logic
        if not is_final_batch and len(self.packet_buffer_raw) < self.timesteps:
             self.logger.warning(f"analyze_packet_batch called with {len(self.packet_buffer_raw)} packets, but expected {self.timesteps}. This should not happen for non-final batches.")
             return

        # Ensure we take only the required number of timesteps for analysis, especially if called externally
        current_batch_packets = self.packet_buffer_raw[:self.timesteps]

        features_list = [self.data_processor.extract_features(p) for p in current_batch_packets]
            
        if features_list: # Check if features_list is not empty
            # Ensure all elements in features_list are dictionaries, otherwise DataFrame creation might fail or produce unexpected results
            if not all(isinstance(f, dict) for f in features_list):
                self.logger.error("Not all extracted features are dictionaries. Skipping batch.")
                return

            df = pd.DataFrame(features_list)
            if df.empty: # Additional check if DataFrame is empty after creation (e.g. if features_list was list of empty dicts)
                self.logger.warning("Features DataFrame is empty after creation. Skipping batch.")
                return

            processed_features_df = self.data_processor.preprocess_data(df)
            
            if processed_features_df.empty: # Check after preprocessing
                self.logger.warning("Features DataFrame is empty after preprocessing. Skipping batch.")
                return

            if processed_features_df.shape[1] != self.num_features:
                self.logger.error(f"DataProcessor output {processed_features_df.shape[1]} features, but model expects {self.num_features}.")
                return
            
            # Ensure we have exactly self.timesteps rows after processing
            if processed_features_df.shape[0] != self.timesteps:
                self.logger.error(f"DataProcessor output {processed_features_df.shape[0]} rows (timesteps), but expected {self.timesteps}.")
                return


            lstm_input_data = processed_features_df.to_numpy()
            lstm_input_data = lstm_input_data.reshape((1, self.timesteps, self.num_features))
            
            predictions = self.ids_model.predict(lstm_input_data)
            
            if predictions.ndim == 2 and predictions.shape[0] == 1 and predictions.shape[1] == 1:
                prediction_value = predictions[0][0]
                if prediction_value > self.threshold:
                    last_packet_in_sequence = current_batch_packets[-1]
                    self.handle_intrusion(last_packet_in_sequence, prediction_value)
            else:
                self.logger.error(f"Unexpected prediction shape: {predictions.shape}. Expected (1,1).")
        
    def handle_intrusion(self, packet, confidence):
        src_ip = packet[IP].src if IP in packet else 'N/A'
        dst_ip = packet[IP].dst if IP in packet else 'N/A'
        protocol = packet[IP].proto if IP in packet else 'N/A'
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        alert_msg = (f"Potential intrusion detected for a sequence ending at {timestamp}\n"
                       f"Confidence: {confidence:.2f}\n"
                       f"Details from last packet in sequence: Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
        
        packet_info_dict = {
            'Sequence End Time': timestamp,
            'Confidence': f"{confidence:.2f}",
            'Last Packet Source IP': src_ip,
            'Last Packet Destination IP': dst_ip,
            'Last Packet Protocol': protocol,
            'Sequence Length': self.timesteps
        }
        
        packet_info_str = "\n".join([f"{k}: {v}" for k, v in packet_info_dict.items()])
        self.trigger_alert(alert_msg, packet_info_str)
                
    def start_detection(self):
        self.logger.info(f"Starting live network detection: monitoring for sequences of {self.timesteps} packets.")
        sniff(prn=self.packet_callback, store=False, iface=None)
    
    def process_pcap_file(self, filepath):
        self.logger.info(f"Starting PCAP file processing: {filepath}")
        try:
            packets_from_file = rdpcap(filepath)
        except FileNotFoundError:
            self.logger.error(f"PCAP file not found: {filepath}")
            return
        except Exception as e: # Scapy can raise various errors on malformed files
            self.logger.error(f"Error reading PCAP file {filepath}: {e}")
            return

        self.logger.info(f"Read {len(packets_from_file)} packets from {filepath}.")
        for packet in packets_from_file:
            self.packet_callback(packet) # This will fill buffer and call analyze_packet_batch
        
        # After all packets from file, analyze any remaining packets in the buffer
        if self.packet_buffer_raw: # Check if there's anything left
            self.logger.info(f"Processing final batch of {len(self.packet_buffer_raw)} packets from PCAP.")
            self.analyze_packet_batch(is_final_batch=True)
            self.packet_buffer_raw = [] # Clear buffer afterwards
        
        self.logger.info(f"Finished processing PCAP file: {filepath}")

    def trigger_alert(self, message, packet_info_str):
        self.alert_system.log_alert(message)
        self.alert_system.send_email_alert(
            subject="Network Intrusion Detected (Sequence)",
            message=message,
            packet_info=packet_info_str
        )
