import smtplib
import csv
from email.message import EmailMessage
import ssl 
from config import (
    SMTP_SERVER, SMTP_PORT, EMAIL_ADDRESS, EMAIL_PASSWORD,
    RECIPIENTS_FILE, TEMPLATE_FILE
)
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_recipients(filename):
    """Reads recipients from a CSV file, trying both UTF-16 and UTF-8 encodings."""
    recipients = []
    encodings = ['utf-16', 'utf-8']
    
    for file_encoding in encodings:
        try:
            with open(filename, mode='r', encoding=file_encoding, newline='') as file:
                reader = csv.DictReader(file)
                # Check header after successful read
                if not reader.fieldnames:
                    logging.error(f"CSV file '{filename}' appears to be empty or header is missing (using encoding {file_encoding}).")
                    continue
                if not all(col in reader.fieldnames for col in ['email', 'name']):
                    logging.error(f"CSV file '{filename}' must contain 'email' and 'name' columns. Found columns: {reader.fieldnames} (using encoding {file_encoding})")
                    continue
                # Read all rows if header is correct
                recipients = list(reader)
                logging.info(f"Successfully read {len(recipients)} recipients from {filename} using {file_encoding} encoding.")
                return recipients
        except UnicodeDecodeError:
            logging.warning(f"Failed to decode {filename} with {file_encoding} encoding. Trying next encoding...")
        except FileNotFoundError:
            logging.error(f"Recipients file not found: {filename}")
            return []
        except Exception as e:
            logging.error(f"Error reading recipients file {filename} (using encoding {file_encoding}): {e}")
    
    if not recipients:
        logging.error(f"Could not read recipients file with any supported encodings: {encodings}")
    return recipients

def read_template(filename):
    """Reads the email template from a file, trying both UTF-16 and UTF-8 encodings."""
    template = None
    encodings = ['utf-16', 'utf-8']
    
    for file_encoding in encodings:
        try:
            with open(filename, mode='r', encoding=file_encoding) as file:
                template = file.read()
            logging.info(f"Successfully read template file: {filename} using {file_encoding} encoding.")
            return template
        except UnicodeDecodeError:
            logging.warning(f"Failed to decode {filename} with {file_encoding} encoding. Trying next encoding...")
        except FileNotFoundError:
            logging.error(f"Template file not found: {filename}")
            return None
        except Exception as e:
            logging.error(f"Error reading template file {filename} (using encoding {file_encoding}): {e}")
    
    if template is None:
        logging.error(f"Could not read template file with any supported encodings: {encodings}")
    return template

def send_emails(recipients, template_html):
    """Connects to the SMTP server and sends emails to recipients."""
    if not recipients or not template_html:
        logging.warning("No recipients or template loaded. Aborting email sending.")
        return

    context = ssl.create_default_context() # For secure TLS connection

    try:
        logging.info(f"Connecting to SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls(context=context)  # Secure the connection
            logging.info("Connection secured with TLS.")
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            logging.info("Successfully logged into SMTP server.")

            for recipient in recipients:
                try:
                    msg = EmailMessage()
                    
                    # Safely format the template by escaping existing braces first
                    # This changes { to {{ and } to }} for non-placeholder braces
                    safe_template = template_html.replace('{', '{{').replace('}', '}}')
                    
                    # Now restore our intended placeholders by changing back {{name}} to {name}
                    safe_template = safe_template.replace('{{name}}', '{name}').replace('{{email}}', '{email}')
                    
                    # Now format with recipient data
                    personalized_body = safe_template.format(
                        name=recipient.get('name', 'Valued Customer'),
                        email=recipient['email']
                    )

                    msg.set_content("Please enable HTML to view this email.") # Fallback for non-HTML clients
                    msg.add_alternative(personalized_body, subtype='html')

                    msg['Subject'] = "Test Email XEA"
                    # Format the From header to include a display name
                    msg['From'] = f"Xea-Strike <{EMAIL_ADDRESS}>"
                    msg['To'] = recipient['email']
                    # Keep the Reply-To header if you still want replies directed elsewhere
                    msg['Reply-To'] = EMAIL_ADDRESS

                    server.send_message(msg)
                    logging.info(f"Successfully sent email to {recipient['email']}")

                except KeyError as e:
                    logging.error(f"Missing key {e} for recipient {recipient.get('email', 'N/A')}. Skipping.")
                except Exception as e:
                    logging.error(f"Failed to send email to {recipient.get('email', 'N/A')}: {e}")

        logging.info("Finished sending all emails.")

    except smtplib.SMTPAuthenticationError:
        logging.error("SMTP Authentication Error: Check email address and password/app password.")
    except smtplib.SMTPConnectError:
        logging.error(f"Failed to connect to the SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
    except ConnectionRefusedError:
         logging.error(f"Connection refused by the server: {SMTP_SERVER}:{SMTP_PORT}. Check server/port and firewall.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during SMTP operation: {e}")


if __name__ == "__main__":
    logging.info("Starting email sending script...")
    # 1. Read configuration (done via import from config.py)
    # 2. Read recipients
    recipient_list = read_recipients(RECIPIENTS_FILE)
    # 3. Read template
    email_template = read_template(TEMPLATE_FILE)
    # 4. Send emails
    send_emails(recipient_list, email_template)
    logging.info("Email sending script finished.")