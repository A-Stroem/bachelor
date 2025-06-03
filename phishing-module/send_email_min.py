import smtplib, csv, ssl
from email.message import EmailMessage
from config import SMTP_SERVER, SMTP_PORT, EMAIL_ADDRESS, EMAIL_PASSWORD, RECIPIENTS_FILE, TEMPLATE_FILE

def read_recipients(filename):
    with open(filename, mode='r', encoding='utf-16', newline='') as file:
        return list(csv.DictReader(file))

def read_template(filename):
    with open(filename, mode='r', encoding='utf-16') as file:
        return file.read()

def send_emails(recipients, template_html):
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        for recipient in recipients:
            msg = EmailMessage()
            personalized_body = template_html.format(
                name=recipient.get('name', 'Valued Customer'),
                email=recipient['email']
            )
            msg.set_content("Please enable HTML to view this email.")
            msg.add_alternative(personalized_body, subtype='html')
            msg['Subject'] = "Test Email XEA"
            msg['From'] = EMAIL_ADDRESS
            msg['To'] = recipient['email']
            server.send_message(msg)
            print(f"Sent to {recipient['email']}") 

if __name__ == "__main__":
    print("Starting...")
    recipient_list = read_recipients(RECIPIENTS_FILE)
    email_template = read_template(TEMPLATE_FILE)
    send_emails(recipient_list, email_template)
    print("Finished.")