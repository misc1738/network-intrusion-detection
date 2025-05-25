<<<<<<< HEAD
# Network Intrusion Detection System (NIDS)

A machine learning-powered Network Intrusion Detection System that uses TensorFlow and deep learning to detect potential network intrusions in real-time.

## Features

- Real-time network traffic monitoring using Scapy
- Advanced packet analysis with comprehensive feature extraction
- LSTM-based deep learning model for intrusion detection
- Batch processing of network packets for efficient analysis
- Automated alert system with email notifications
- Sophisticated data preprocessing and feature engineering
- Class imbalance handling using SMOTE

## Requirements

- Python 3.8+
- TensorFlow 2.8.0+
- Other dependencies listed in requirements.txt

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. Configure email alerts in the NetworkDetector initialization:
   ```python
   smtp_config = {
       'server': 'smtp.gmail.com',
       'port': 587,
       'username': 'your-email@gmail.com',
       'password': 'your-app-password',
       'recipients': ['recipient@example.com']
   }
   ```

## Usage

Run the main script to start the intrusion detection system:

```bash
python src/main.py
```

## Architecture

- `main.py`: Entry point of the application
- `model.py`: LSTM-based neural network model
- `detector.py`: Network traffic monitoring and analysis
- `data_processor.py`: Feature extraction and preprocessing
- `alert_system.py`: Alert generation and notification system

## Alert System

The system generates alerts when potential intrusions are detected:

- Logs alerts to file system
- Sends email notifications with detailed packet information
- Configurable alert thresholds

## Data Processing

### Features Extracted:

- Packet size and protocol information
- TCP/UDP specific features
- IP header information
- Payload entropy
- Port information
- Packet flags

### Preprocessing:

- Numerical feature normalization
- Categorical feature encoding
- Missing value handling
- Class imbalance correction

## Security Considerations

- Network traffic monitoring should be restricted to trusted networks
- Store SMTP credentials securely
- Regular model updates recommended
- Monitor false positive rates
- Keep dependencies updated
=======
# Network Intrusion Detection System (NIDS)

A machine learning-powered Network Intrusion Detection System that uses TensorFlow and deep learning to detect potential network intrusions in real-time.

## Features

- Real-time network traffic monitoring using Scapy
- Advanced packet analysis with comprehensive feature extraction
- LSTM-based deep learning model for intrusion detection
- Batch processing of network packets for efficient analysis
- Automated alert system with email notifications
- Sophisticated data preprocessing and feature engineering
- Class imbalance handling using SMOTE

## Requirements

- Python 3.8+
- TensorFlow 2.8.0+
- Other dependencies listed in requirements.txt

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. Configure email alerts in the NetworkDetector initialization:
   ```python
   smtp_config = {
       'server': 'smtp.gmail.com',
       'port': 587,
       'username': 'your-email@gmail.com',
       'password': 'your-app-password',
       'recipients': ['recipient@example.com']
   }
   ```

## Usage

Run the main script to start the intrusion detection system:

```bash
python src/main.py
```

## Architecture

- `main.py`: Entry point of the application
- `model.py`: LSTM-based neural network model
- `detector.py`: Network traffic monitoring and analysis
- `data_processor.py`: Feature extraction and preprocessing
- `alert_system.py`: Alert generation and notification system

## Alert System

The system generates alerts when potential intrusions are detected:

- Logs alerts to file system
- Sends email notifications with detailed packet information
- Configurable alert thresholds

## Data Processing

### Features Extracted:

- Packet size and protocol information
- TCP/UDP specific features
- IP header information
- Payload entropy
- Port information
- Packet flags

### Preprocessing:

- Numerical feature normalization
- Categorical feature encoding
- Missing value handling
- Class imbalance correction

## Security Considerations

- Network traffic monitoring should be restricted to trusted networks
- Store SMTP credentials securely
- Regular model updates recommended
- Monitor false positive rates
- Keep dependencies updated
>>>>>>> b565a2a6b0be06d24c15e7b22047cad86b3637b5
