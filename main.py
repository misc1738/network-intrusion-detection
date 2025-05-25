from detector import NetworkDetector
from model import IntrusionDetectionModel
import configparser
import os
import logging
import tensorflow as tf # For tf.keras.models.load_model, though used in model.py primarily
import argparse # For command-line arguments

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument("--pcap", type=str, default=None, 
                        help="Path to a PCAP file to process. If not provided, starts live sniffing.")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    if not os.path.exists('config.ini'):
        logging.error("Error: config.ini not found. Please create it with necessary configurations.")
        exit(1)
    config.read('config.ini')

    timesteps = config['Model'].getint('timesteps', 10)
    features = config['Model'].getint('features', 14) 
    model_save_path = config['Paths'].get('model_save_path', 'model/intrusion_model.h5')
    
    ids_model = IntrusionDetectionModel(timesteps=timesteps, features=features)
    
    if os.path.exists(model_save_path):
        logging.info(f"Found saved model at {model_save_path}. Attempting to load...")
        ids_model.load_existing_model(model_save_path)
    else:
        logging.warning(f"No saved model found at {model_save_path}. Proceeding with a new/untrained model.")
        logging.warning("Consider running train_model.py to train and save a model.")
    
    detector = NetworkDetector(ids_model)
    
    if args.pcap:
        pcap_file_path = args.pcap
        if os.path.exists(pcap_file_path):
            logging.info(f"PCAP file provided: {pcap_file_path}. Starting PCAP processing.")
            detector.process_pcap_file(pcap_file_path)
        else:
            logging.error(f"PCAP file not found: {pcap_file_path}. Exiting.")
            exit(1)
    else:
        logging.info("No PCAP file provided. Starting live network sniffing.")
        detector.start_detection()

if __name__ == "__main__":
    main()
