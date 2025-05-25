import argparse
import configparser
import numpy as np
import pandas as pd
from scapy.all import rdpcap # Using rdpcap for simplicity, consider PcapReader for very large files
from data_processor import DataProcessor
from model import IntrusionDetectionModel
import os
from sklearn.model_selection import train_test_split
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_and_prepare_data(pcap_path, data_processor, timesteps, num_features, abnormal_ratio, random_seed=42):
    logging.info(f"Loading packets from {pcap_path}...")
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        logging.error(f"PCAP file not found: {pcap_path}")
        return None, None
    except Exception as e:
        logging.error(f"Error reading PCAP file {pcap_path}: {e}")
        return None, None

    if not packets:
        logging.warning("No packets found in PCAP file.")
        return None, None

    logging.info(f"Extracting features from {len(packets)} packets...")
    features_list = [data_processor.extract_features(p) for p in packets]
    features_df = pd.DataFrame(features_list)

    # Preprocess features (scaling, encoding) - SMOTE will be applied after this
    logging.info("Preprocessing features...")
    processed_features_df = data_processor.preprocess_data(features_df.copy()) # Use a copy

    # --- Artificial Label Generation (Packet Level) ---
    num_total_packets = len(processed_features_df)
    packet_labels = np.zeros(num_total_packets, dtype=int)
    num_abnormal_packets = int(num_total_packets * abnormal_ratio)
    if num_abnormal_packets > 0 and num_total_packets > 0:
        np.random.seed(random_seed) # for reproducibility
        abnormal_indices = np.random.choice(num_total_packets, num_abnormal_packets, replace=False)
        packet_labels[abnormal_indices] = 1
        logging.info(f"Artificially labeled {num_abnormal_packets} packets as abnormal (1), out of {num_total_packets} total packets.")
    else:
        logging.info("No packets labeled as abnormal based on abnormal_ratio or total packet count.")

    # --- Apply SMOTE (if there are any positive labels) ---
    if np.sum(packet_labels) > 0 and np.sum(packet_labels) < len(packet_labels):
        logging.info("Applying SMOTE to balance packet-level classes...")
        # apply_smote expects X_df and y_series (pandas Series)
        processed_features_df, packet_labels_series_resampled = data_processor.apply_smote(
            processed_features_df, pd.Series(packet_labels)
        )
        # apply_smote returns X as DataFrame, y as Series. Convert y back to numpy array.
        packet_labels = packet_labels_series_resampled.to_numpy()
        logging.info(f"Data resampled with SMOTE. New feature count: {len(processed_features_df)}, New label count: {len(packet_labels)}")
    elif np.sum(packet_labels) == 0:
        logging.warning("No positive samples (abnormal packets) to apply SMOTE. Training might be ineffective.")
    else: # All samples are positive, or no samples - SMOTE not applicable or needed
        logging.info("SMOTE not applied as all samples are of the same class or no data.")


    # --- Sequence Creation ---
    logging.info(f"Creating sequences of length {timesteps}...")
    sequences = []
    sequence_labels = []
    
    # processed_features_df is now a DataFrame after SMOTE (or original if SMOTE wasn't applied)
    # Ensure it has the correct number of features
    if processed_features_df.shape[1] != num_features:
        logging.error(f"Feature mismatch: Expected {num_features} features, got {processed_features_df.shape[1]} after preprocessing/SMOTE. Check DataProcessor.ALL_FEATURE_NAMES.")
        # Fallback to using all features from the df, this might mismatch model input
        # It is better to ensure num_features in config matches DataProcessor output
        # For now, we will proceed but log a strong warning.
        # num_features = processed_features_df.shape[1] # This would be a runtime adjustment, better to fix config

    # Convert DataFrame to NumPy array for sequence creation
    data_np = processed_features_df.to_numpy()

    for i in range(len(data_np) - timesteps + 1):
        sequences.append(data_np[i:i + timesteps])
        # Label sequence as abnormal if any packet in it was abnormal
        # This uses the packet_labels array which corresponds to rows in data_np
        current_sequence_packet_labels = packet_labels[i:i + timesteps]
        sequence_labels.append(1 if np.any(current_sequence_packet_labels == 1) else 0)
    
    if not sequences:
        logging.warning("No sequences created. Check PCAP length and timesteps.")
        return None, None

    X = np.array(sequences)
    y = np.array(sequence_labels)
    logging.info(f"Created {len(X)} sequences. Shape X: {X.shape}, Shape y: {y.shape}")
    logging.info(f"Class distribution in sequences - Normal (0): {np.sum(y == 0)}, Abnormal (1): {np.sum(y == 1)}")

    return X, y

def main():
    parser = argparse.ArgumentParser(description="Train Intrusion Detection Model")
    parser.add_argument("--pcap", type=str, required=True, help="Path to the input PCAP file for training.")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs.")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size for training.")
    parser.add_argument("--abnormal_ratio", type=float, default=0.1, help="Fraction of sequences to artificially label as abnormal.")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    if not os.path.exists('config.ini'):
        logging.error("config.ini not found! Please ensure it exists in the root directory.")
        return
    config.read('config.ini')

    timesteps = config['Model'].getint('timesteps', 10)
    num_features = config['Model'].getint('features', 14) # Should match DataProcessor.ALL_FEATURE_NAMES
    model_save_path = config['Paths'].get('model_save_path', 'model/intrusion_model.h5')

    # Ensure model save directory exists
    model_save_dir = os.path.dirname(model_save_path)
    if not os.path.exists(model_save_dir):
        os.makedirs(model_save_dir, exist_ok=True)
        logging.info(f"Created directory for saving model: {model_save_dir}")

    data_processor = DataProcessor()
    
    X, y = load_and_prepare_data(args.pcap, data_processor, timesteps, num_features, args.abnormal_ratio)

    if X is None or y is None or len(X) == 0:
        logging.error("Failed to load or prepare data. Exiting training.")
        return
    
    if X.shape[2] != num_features:
        logging.error(f"CRITICAL: Mismatch between data features ({X.shape[2]}) and configured features ({num_features}). Training aborted. Please check DataProcessor output and config.ini.")
        return

    # Initialize model
    ids_model = IntrusionDetectionModel(timesteps=timesteps, features=num_features)
    logging.info(f"Initialized model with timesteps={timesteps}, features={num_features}")

    # Split data
    if len(X) < 2:
        logging.error("Not enough data to split into training and validation sets. Need at least 2 sequences.")
        # Potentially train on the single sample if that's desired, but usually not.
        return
        
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y if np.sum(y)>1 else None)
    logging.info(f"Data split: X_train shape: {X_train.shape}, y_train shape: {y_train.shape}, X_val shape: {X_val.shape}, y_val shape: {y_val.shape}")

    logging.info(f"Starting model training for {args.epochs} epochs with batch size {args.batch_size}...")
    ids_model.train(X_train, y_train, epochs=args.epochs, batch_size=args.batch_size, validation_data=(X_val, y_val))

    logging.info(f"Training complete. Saving model to {model_save_path}...")
    ids_model.model.save(model_save_path)
    logging.info(f"Model saved successfully to {model_save_path}")

if __name__ == "__main__":
    main()
