import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from datetime import datetime
import configparser
import os
import sys # For StreamHandler default stream

class AlertSystem:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')

        self.smtp_config = {}
        if 'SMTP' in config:
            self.smtp_config['server'] = config['SMTP'].get('server', 'smtp.gmail.com')
            self.smtp_config['port'] = config['SMTP'].getint('port', 587)
            self.smtp_config['username'] = config['SMTP'].get('username')
            self.smtp_config['password'] = config['SMTP'].get('password')
            recipients_str = config['SMTP'].get('recipients', '')
            self.smtp_config['recipients'] = [r.strip() for r in recipients_str.split(',') if r.strip()]
            self.smtp_config['enable_email_alerts'] = config['SMTP'].getboolean('enable_email_alerts', False)
        else:
            self.smtp_config = {
                'server': 'smtp.gmail.com',
                'port': 587,
                'username': None,
                'password': None,
                'recipients': [],
                'enable_email_alerts': False
            }
            logging.warning("SMTP configuration section not found in config.ini. Email alerts will be disabled or use defaults.")
        
        self.config = config
        self.setup_logging()
    
    def setup_logging(self):
        self.logger = logging.getLogger('AlertSystem')
        self.logger.setLevel(logging.INFO) # Set level for the logger itself
        
        # Prevent adding multiple handlers if setup_logging is called again (e.g. in tests)
        if not self.logger.handlers:
            log_file_path = self.config['Paths'].get('log_file', 'logs/alerts.log')
            log_dir = os.path.dirname(log_file_path)
            if log_dir and not os.path.exists(log_dir): # Check if log_dir is not empty string
                os.makedirs(log_dir, exist_ok=True)
                
            # File Handler
            file_handler = logging.FileHandler(log_file_path)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.INFO) # Can set level per handler
            self.logger.addHandler(file_handler)
            
            # Console Handler
            console_handler = logging.StreamHandler(sys.stdout) # Log to stdout
            console_handler.setFormatter(formatter) # Use the same formatter
            console_handler.setLevel(logging.INFO) # Can set level per handler
            self.logger.addHandler(console_handler)
            
            self.logger.propagate = False # Prevent root logger from duplicating messages if it's also configured

    def send_email_alert(self, subject, message, packet_info):
        if not self.smtp_config.get('enable_email_alerts'):
            self.logger.info("Email alerts are disabled in config.ini. Alert not sent.")
            return False
            
        if not all([self.smtp_config.get('username'), self.smtp_config.get('password'), self.smtp_config.get('recipients')]):
            self.logger.warning("Email configuration incomplete (username, password, or recipients missing). Alert not sent.")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config['username']
            msg['To'] = ', '.join(self.smtp_config['recipients'])
            msg['Subject'] = f"[NIDS Alert] {subject}"

            body = f"""
            Intrusion Detection Alert
            -------------------------
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Message: {message}
            
            Packet Details:
            {packet_info}
            """

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'])
            server.starttls()
            server.login(self.smtp_config['username'], self.smtp_config['password'])
            server.send_message(msg)
            server.quit()

            self.logger.info(f"Alert email sent successfully: {subject}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to send email alert: {str(e)}")
            return False

    def log_alert(self, message, severity='WARNING'):
        log_level = logging.WARNING if severity == 'WARNING' else logging.CRITICAL
        self.logger.log(log_level, message)
