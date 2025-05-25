import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from datetime import datetime

class AlertSystem:
    def __init__(self, smtp_config=None):
        self.smtp_config = smtp_config or {
            'server': 'smtp.gmail.com',
            'port': 587,
            'username': None,
            'password': None,
            'recipients': []
        }
        self.setup_logging()
    
    def setup_logging(self):
        self.logger = logging.getLogger('AlertSystem')
        if not self.logger.handlers:
            handler = logging.FileHandler('logs/alerts.log')
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def send_email_alert(self, subject, message, packet_info):
        if not all([self.smtp_config['username'], self.smtp_config['password'], self.smtp_config['recipients']]):
            self.logger.warning("Email configuration incomplete. Alert not sent.")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config['username']
            msg['To'] = ', '.join(self.smtp_config['recipients'])
            msg['Subject'] = f"[NIDS Alert] {subject}"

            body = f"""
            Intrusion Detection Alert
            -------------------------
            Time: {datetime.now()}
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
        """Log alerts to file system"""
        self.logger.log(
            logging.WARNING if severity == 'WARNING' else logging.CRITICAL,
            message
        )