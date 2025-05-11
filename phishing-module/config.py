import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Email Server Configuration
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))  # Default to 587 if not set
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD') # Consider using app passwords for services like Gmail

# File Paths
RECIPIENTS_FILE = os.path.join('data', 'recipients.csv')
TEMPLATE_FILE = os.path.join('templates', 'microsoft_password_update.html')

# Basic validation (optional but recommended)
if not all([SMTP_SERVER, EMAIL_ADDRESS, EMAIL_PASSWORD]):
    raise ValueError("Missing required environment variables: SMTP_SERVER, EMAIL_ADDRESS, EMAIL_PASSWORD")


