import subprocess
import time
import sys
import os

# --- CONFIGURATION ---
PHISHING_MODULE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'phishing-module'))
RECIPIENTS_FILE = os.path.join(PHISHING_MODULE_PATH, 'data', 'recipients.csv')
CLICKFIX_TEMPLATE = os.path.join(os.path.dirname(__file__), 'public', 'clickfix.html')

# --- 1. Start the ClickFix Express server ---
def start_clickfix_server():
    print("Starting ClickFix Express server with npm start...")
    npm_path = r"C:\Program Files\nodejs\npm.cmd"  # Update if your path is different
    proc = subprocess.Popen([npm_path, 'start'], cwd=os.path.dirname(__file__))
    time.sleep(5)
    return proc

# --- 2. Send emails using the clickfix template ---
def send_clickfix_emails():
    from phishing_module.send_email import read_recipients, read_template, send_emails
    recipients = read_recipients(RECIPIENTS_FILE)
    with open(CLICKFIX_TEMPLATE, encoding='utf-8') as f:
        template_html = f.read()
    send_emails(recipients, template_html)

if __name__ == "__main__":
    server_proc = start_clickfix_server()
    try:
        send_clickfix_emails()
        print("Emails sent. ClickFix server is running.")
        print("Press Ctrl+C to stop the server.")
        server_proc.wait()  # Keep the script running as long as the server is up
    except KeyboardInterrupt:
        print("Shutting down ClickFix server...")
        server_proc.terminate()
        server_proc.wait()
