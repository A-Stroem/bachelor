#!/usr/bin/env python3
"""
TCP Listener for ClickFix simulation
Listens on port 9999 for incoming data and displays it in the console
"""

import socket
import threading
import time
import sys
from datetime import datetime

class TCPListener:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.connections = []
        
    def start_listener(self):
        """Start the TCP listener server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔊 TCP Listener started on {self.host}:{self.port}")
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 📡 Waiting for connections...")
            
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)  # Non-blocking accept
                    client_socket, client_address = self.server_socket.accept()
                    
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔗 Connection from {client_address}")
                    
                    # Handle client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue  # Continue listening
                except OSError:
                    break  # Server socket closed
                    
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Error starting TCP listener: {e}")
        finally:
            self.stop_listener()
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        try:
            self.connections.append(client_socket)
            
            while self.running:
                try:
                    # Receive data from client
                    data = client_socket.recv(1024)
                    if not data:
                        break
                        
                    # Decode and display the message
                    message = data.decode('utf-8', errors='ignore').strip()
                    if message:
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        print(f"[{timestamp}] 📨 Data from {client_address[0]}:{client_address[1]}")
                        print(f"[{timestamp}] 💬 Message: {message}")
                        print(f"[{timestamp}] " + "="*50)
                        
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break
                except Exception as e:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠️  Error handling client {client_address}: {e}")
                    break
                    
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Client handler error: {e}")
        finally:
            try:
                client_socket.close()
                if client_socket in self.connections:
                    self.connections.remove(client_socket)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔌 Disconnected from {client_address}")
            except:
                pass
    
    def stop_listener(self):
        """Stop the TCP listener server"""
        self.running = False
        
        # Close all client connections
        for conn in self.connections[:]:
            try:
                conn.close()
            except:
                pass
        self.connections.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔇 TCP Listener stopped")

def run_listener():
    """Main function to run the TCP listener"""
    listener = TCPListener()
    
    try:
        listener.start_listener()
    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 🛑 Received interrupt signal")
    finally:
        listener.stop_listener()

if __name__ == "__main__":
    run_listener()
