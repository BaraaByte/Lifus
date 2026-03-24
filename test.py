import socket
import json
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("System Controller Client")
        self.root.geometry("800x600")
        
        self.server_host = 'localhost'
        self.server_port = 5000
        self.client_socket = None
        self.connected = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Connection Frame
        conn_frame = ttk.LabelFrame(self.root, text="Connection", padding=10)
        conn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(conn_frame, text="Server:").grid(row=0, column=0, sticky='w')
        self.host_entry = ttk.Entry(conn_frame, width=20)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky='w', padx=(10,0))
        self.port_entry = ttk.Entry(conn_frame, width=6)
        self.port_entry.insert(0, "5000")
        self.port_entry.grid(row=0, column=3, padx=5)
        
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=4, padx=10)
        
        self.status_label = ttk.Label(conn_frame, text="● Disconnected", foreground="red")
        self.status_label.grid(row=0, column=5, padx=10)
        
        # Apps Frame
        apps_frame = ttk.LabelFrame(self.root, text="Running Applications", padding=10)
        apps_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview for apps
        self.apps_tree = ttk.Treeview(apps_frame, columns=('name', 'pid'), show='headings', height=10)
        self.apps_tree.heading('name', text='Application Name')
        self.apps_tree.heading('pid', text='Process ID')
        self.apps_tree.column('name', width=400)
        self.apps_tree.column('pid', width=100)
        self.apps_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        refresh_btn = ttk.Button(apps_frame, text="Refresh Apps", command=self.refresh_apps)
        refresh_btn.pack(pady=5)
        
        # Control Frame
        control_frame = ttk.LabelFrame(self.root, text="System Control", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        # Button frame for system controls
        button_frame = ttk.Frame(control_frame)
        button_frame.pack()
        
        self.poweroff_btn = ttk.Button(button_frame, text="Power Off", command=lambda: self.send_command('poweroff'), state='disabled')
        self.poweroff_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.restart_btn = ttk.Button(button_frame, text="Restart", command=lambda: self.send_command('restart'), state='disabled')
        self.restart_btn.grid(row=0, column=1, padx=5, pady=5)
        
        self.sleep_btn = ttk.Button(button_frame, text="Sleep", command=lambda: self.send_command('sleep'), state='disabled')
        self.sleep_btn.grid(row=0, column=2, padx=5, pady=5)
        
        self.lock_btn = ttk.Button(button_frame, text="Lock", command=lambda: self.send_command('lock'), state='disabled')
        self.lock_btn.grid(row=0, column=3, padx=5, pady=5)
        
        # Log Frame
        log_frame = ttk.LabelFrame(self.root, text="Command Log", padding=10)
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, width=70)
        self.log_text.pack(fill='both', expand=True)
        
    def log_message(self, message, is_error=False):
        """Add message to log"""
        timestamp = time.strftime("%H:%M:%S")
        if is_error:
            self.log_text.insert(tk.END, f"[{timestamp}] ERROR: {message}\n", 'error')
            self.log_text.tag_config('error', foreground='red')
        else:
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def toggle_connection(self):
        """Connect or disconnect from server"""
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()
    
    def connect_to_server(self):
        """Connect to the server"""
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            
            self.connected = True
            self.connect_btn.config(text="Disconnect")
            self.status_label.config(text="● Connected", foreground="green")
            
            # Enable control buttons
            self.poweroff_btn.config(state='normal')
            self.restart_btn.config(state='normal')
            self.sleep_btn.config(state='normal')
            self.lock_btn.config(state='normal')
            
            self.log_message(f"Connected to server at {host}:{port}")
            
            # Refresh apps list
            self.refresh_apps()
            
        except Exception as e:
            self.log_message(f"Connection failed: {e}", is_error=True)
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
    
    def disconnect_from_server(self):
        """Disconnect from server"""
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        
        self.connected = False
        self.connect_btn.config(text="Connect")
        self.status_label.config(text="● Disconnected", foreground="red")
        
        # Disable control buttons
        self.poweroff_btn.config(state='disabled')
        self.restart_btn.config(state='disabled')
        self.sleep_btn.config(state='disabled')
        self.lock_btn.config(state='disabled')
        
        self.log_message("Disconnected from server")
    
    def send_command(self, command):
        """Send command to server"""
        if not self.connected or not self.client_socket:
            self.log_message("Not connected to server", is_error=True)
            return
        
        try:
            # Confirm before destructive commands
            if command in ['poweroff', 'restart', 'sleep']:
                result = messagebox.askyesno(
                    "Confirm", 
                    f"Are you sure you want to {command} the server?"
                )
                if not result:
                    return
            
            command_data = json.dumps({'command': command})
            self.client_socket.send(command_data.encode('utf-8'))
            
            # Receive response
            response_data = self.client_socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            
            if response.get('status') == 'success':
                self.log_message(f"Command '{command}' executed successfully: {response.get('message', 'OK')}")
                if command in ['poweroff', 'restart']:
                    self.log_message("Server is shutting down. Connection will be lost.")
                    self.disconnect_from_server()
            else:
                self.log_message(f"Command '{command}' failed: {response.get('message', 'Unknown error')}", is_error=True)
                
        except Exception as e:
            self.log_message(f"Error sending command: {e}", is_error=True)
            self.disconnect_from_server()
    
    def refresh_apps(self):
        """Refresh the list of running applications"""
        if not self.connected or not self.client_socket:
            self.log_message("Cannot refresh apps: not connected", is_error=True)
            return
        
        try:
            # Clear current items
            for item in self.apps_tree.get_children():
                self.apps_tree.delete(item)
            
            command_data = json.dumps({'command': 'get_apps'})
            self.client_socket.send(command_data.encode('utf-8'))
            
            # Receive response
            response_data = self.client_socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            
            if response.get('status') == 'success':
                apps = response.get('apps', [])
                for app in apps:
                    self.apps_tree.insert('', 'end', values=(app['name'], app['pid']))
                self.log_message(f"Refreshed applications list: {len(apps)} apps found")
            else:
                self.log_message(f"Failed to get apps: {response.get('message', 'Unknown error')}", is_error=True)
                
        except Exception as e:
            self.log_message(f"Error refreshing apps: {e}", is_error=True)

def main():
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
