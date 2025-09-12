import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import random
import socket
import struct
import select
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from collections import defaultdict, deque
import ipaddress
import json
import os
from datetime import datetime

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defese Hyper DDOS Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#87CEEB')  # Sky blue background
        
        # Initialize variables
        self.traffic_running = False
        self.traffic_thread = None
        self.target_ip = tk.StringVar()
        self.packet_size = tk.IntVar(value=1024)
        self.packet_rate = tk.IntVar(value=100)
        self.duration = tk.IntVar(value=60)
        self.traffic_type = tk.StringVar(value="TCP")
        self.traffic_data = defaultdict(lambda: deque(maxlen=100))
        self.start_time = None
        
        # Setup styles
        self.setup_styles()
        
        # Create interface
        self.create_menu()
        self.create_dashboard()
        
        # Start data update thread
        self.update_charts()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles with sky blue theme
        style.configure('Sky.TFrame', background='#87CEEB')
        style.configure('Sky.TLabelframe', background='#87CEEB', foreground='#00308F')
        style.configure('Sky.TLabelframe.Label', background='#87CEEB', foreground='#00308F')
        style.configure('Sky.TButton', background='#4682B4', foreground='white')
        style.configure('Sky.TLabel', background='#87CEEB', foreground='#00308F')
        style.configure('Sky.TCheckbutton', background='#87CEEB', foreground='#00308F')
        style.configure('Sky.TRadiobutton', background='#87CEEB', foreground='#00308F')
        style.configure('Header.TLabel', background='#4682B4', foreground='white', font=('Arial', 12, 'bold'))
        
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New", command=self.new_project)
        file_menu.add_command(label="Open", command=self.open_project)
        file_menu.add_command(label="Save", command=self.save_project)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Traffic Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Packet Analysis", command=self.show_packet_analysis)
        view_menu.add_command(label="Network Map", command=self.show_network_map)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Packet Sniffer", command=self.open_packet_sniffer)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        tools_menu.add_command(label="Traffic Generator", command=self.open_traffic_generator)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Appearance", command=self.open_appearance_settings)
        settings_menu.add_command(label="Network", command=self.open_network_settings)
        settings_menu.add_command(label="Notifications", command=self.open_notification_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        self.root.config(menu=menubar)
        
    def create_dashboard(self):
        # Main frame
        main_frame = ttk.Frame(self.root, style='Sky.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(main_frame, style='Sky.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Accurate Cyber Defense Hyper DDOS Dashboard", 
                 font=('Arial', 16, 'bold'), style='Header.TLabel').pack(fill=tk.X, pady=5)
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Traffic Control", style='Sky.TLabelframe')
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # IP address input
        ip_frame = ttk.Frame(control_frame, style='Sky.TFrame')
        ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ip_frame, text="Target IP:", style='Sky.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Entry(ip_frame, textvariable=self.target_ip, width=15).pack(side=tk.LEFT, padx=5)
        self.target_ip.set("127.0.0.1")
        
        # Traffic parameters
        params_frame = ttk.Frame(control_frame, style='Sky.TFrame')
        params_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(params_frame, text="Packet Size:", style='Sky.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Entry(params_frame, textvariable=self.packet_size, width=8).pack(side=tk.LEFT, padx=5)
        ttk.Label(params_frame, text="bytes", style='Sky.TLabel').pack(side=tk.LEFT, padx=5)
        
        ttk.Label(params_frame, text="Rate:", style='Sky.TLabel').pack(side=tk.LEFT, padx=(20, 5))
        ttk.Entry(params_frame, textvariable=self.packet_rate, width=8).pack(side=tk.LEFT, padx=5)
        ttk.Label(params_frame, text="packets/sec", style='Sky.TLabel').pack(side=tk.LEFT, padx=5)
        
        ttk.Label(params_frame, text="Duration:", style='Sky.TLabel').pack(side=tk.LEFT, padx=(20, 5))
        ttk.Entry(params_frame, textvariable=self.duration, width=8).pack(side=tk.LEFT, padx=5)
        ttk.Label(params_frame, text="sec", style='Sky.TLabel').pack(side=tk.LEFT, padx=5)
        
        # Traffic type
        type_frame = ttk.Frame(control_frame, style='Sky.TFrame')
        type_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(type_frame, text="Traffic Type:", style='Sky.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="TCP", variable=self.traffic_type, value="TCP", style='Sky.TRadiobutton').pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="UDP", variable=self.traffic_type, value="UDP", style='Sky.TRadiobutton').pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="ICMP", variable=self.traffic_type, value="ICMP", style='Sky.TRadiobutton').pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(control_frame, style='Sky.TFrame')
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Traffic", command=self.start_traffic, style='Sky.TButton')
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Traffic", command=self.stop_traffic, style='Sky.TButton', state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Charts frame
        charts_frame = ttk.Frame(main_frame, style='Sky.TFrame')
        charts_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left chart (traffic over time)
        left_frame = ttk.Frame(charts_frame, style='Sky.TFrame')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        chart1_frame = ttk.LabelFrame(left_frame, text="Traffic Volume Over Time", style='Sky.TLabelframe')
        chart1_frame.pack(fill=tk.BOTH, expand=True)
        
        self.fig1 = Figure(figsize=(5, 4), dpi=100, facecolor='#E6F2FF')
        self.ax1 = self.fig1.add_subplot(111)
        self.ax1.set_facecolor('#E6F2FF')
        self.canvas1 = FigureCanvasTkAgg(self.fig1, chart1_frame)
        self.canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Right chart (protocol distribution)
        right_frame = ttk.Frame(charts_frame, style='Sky.TFrame')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        chart2_frame = ttk.LabelFrame(right_frame, text="Protocol Distribution", style='Sky.TLabelframe')
        chart2_frame.pack(fill=tk.BOTH, expand=True)
        
        self.fig2 = Figure(figsize=(5, 4), dpi=100, facecolor='#E6F2FF')
        self.ax2 = self.fig2.add_subplot(111)
        self.ax2.set_facecolor('#E6F2FF')
        self.canvas2 = FigureCanvasTkAgg(self.fig2, chart2_frame)
        self.canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Bottom frame for statistics
        stats_frame = ttk.LabelFrame(main_frame, text="Traffic Statistics", style='Sky.TLabelframe')
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Statistics labels
        stats_subframe = ttk.Frame(stats_frame, style='Sky.TFrame')
        stats_subframe.pack(fill=tk.X, pady=5)
        
        self.sent_label = ttk.Label(stats_subframe, text="Packets Sent: 0", style='Sky.TLabel')
        self.sent_label.pack(side=tk.LEFT, padx=20)
        
        self.rate_label = ttk.Label(stats_subframe, text="Current Rate: 0 pps", style='Sky.TLabel')
        self.rate_label.pack(side=tk.LEFT, padx=20)
        
        self.elapsed_label = ttk.Label(stats_subframe, text="Elapsed Time: 0s", style='Sky.TLabel')
        self.elapsed_label.pack(side=tk.LEFT, padx=20)
        
        self.remaining_label = ttk.Label(stats_subframe, text="Remaining: 0s", style='Sky.TLabel')
        self.remaining_label.pack(side=tk.LEFT, padx=20)
        
    def start_traffic(self):
        if not self.validate_ip():
            messagebox.showerror("Error", "Please enter a valid IP address")
            return
            
        self.traffic_running = True
        self.start_time = time.time()
        self.packets_sent = 0
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Start traffic generation in a separate thread
        self.traffic_thread = threading.Thread(target=self.generate_traffic)
        self.traffic_thread.daemon = True
        self.traffic_thread.start()
        
    def stop_traffic(self):
        self.traffic_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
    def validate_ip(self):
        try:
            ipaddress.ip_address(self.target_ip.get())
            return True
        except ValueError:
            return False
            
    def generate_traffic(self):
        target = self.target_ip.get()
        packet_size = self.packet_size.get()
        packet_rate = self.packet_rate.get()
        duration = self.duration.get()
        traffic_type = self.traffic_type.get()
        
        end_time = time.time() + duration
        packet_count = 0
        
        # Initialize traffic data
        self.traffic_data['time'] = deque(maxlen=100)
        self.traffic_data['volume'] = deque(maxlen=100)
        self.traffic_data['protocols'] = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
        
        try:
            if traffic_type == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # We'll use a raw socket for TCP to avoid connection setup
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            elif traffic_type == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            else:  # ICMP
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                
            # Set IP header included
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            while self.traffic_running and time.time() < end_time:
                # Generate random payload
                payload = os.urandom(packet_size)
                
                # Send packet based on type
                if traffic_type == "TCP":
                    self.send_tcp_packet(sock, target, payload)
                elif traffic_type == "UDP":
                    self.send_udp_packet(sock, target, payload)
                else:  # ICMP
                    self.send_icmp_packet(sock, target, payload)
                
                # Update statistics
                packet_count += 1
                self.packets_sent = packet_count
                self.traffic_data['protocols'][traffic_type] += 1
                
                # Control rate
                time.sleep(1.0 / packet_rate)
                
        except Exception as e:
            print(f"Error generating traffic: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
                
            self.traffic_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
    def send_tcp_packet(self, sock, target, payload):
        # Create IP header
        ip_header = self.create_ip_header(target, socket.IPPROTO_TCP)
        
        # Create TCP header (simplified)
        tcp_header = self.create_tcp_header()
        
        # Combine headers and payload
        packet = ip_header + tcp_header + payload
        
        # Send packet
        sock.sendto(packet, (target, 0))
        
    def send_udp_packet(self, sock, target, payload):
        # Create IP header
        ip_header = self.create_ip_header(target, socket.IPPROTO_UDP)
        
        # Create UDP header (simplified)
        udp_header = self.create_udp_header(len(payload))
        
        # Combine headers and payload
        packet = ip_header + udp_header + payload
        
        # Send packet
        sock.sendto(packet, (target, 0))
        
    def send_icmp_packet(self, sock, target, payload):
        # Create IP header
        ip_header = self.create_ip_header(target, socket.IPPROTO_ICMP)
        
        # Create ICMP header (simplified echo request)
        icmp_header = self.create_icmp_header()
        
        # Combine headers and payload
        packet = ip_header + icmp_header + payload
        
        # Send packet
        sock.sendto(packet, (target, 0))
        
    def create_ip_header(self, target, protocol):
        # Simplified IP header creation
        version_ihl = 69  # Version 4, IHL 5 (5 * 4 = 20 bytes)
        tos = 0           # Type of service
        total_length = 0  # Will be calculated later
        identification = random.randint(0, 65535)
        flags_fragment = 0x4000  # Don't fragment
        ttl = 64
        protocol = protocol
        checksum = 0      # Will be calculated later
        source = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
        dest = socket.inet_aton(target)
        
        # Create header without checksum
        header = struct.pack('!BBHHHBBH4s4s', 
                           version_ihl, tos, total_length, identification, 
                           flags_fragment, ttl, protocol, checksum, source, dest)
        
        # Calculate checksum (simplified)
        checksum = self.calculate_checksum(header)
        
        # Repack with checksum
        header = struct.pack('!BBHHHBBH4s4s', 
                           version_ihl, tos, total_length, identification, 
                           flags_fragment, ttl, protocol, checksum, source, dest)
        
        return header
        
    def create_tcp_header(self):
        # Simplified TCP header
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 1023)
        seq_num = random.randint(0, 4294967295)
        ack_num = 0
        data_offset = 5 << 4  # 5 * 4 = 20 bytes
        flags = 0x02  # SYN flag
        window = socket.htons(5840)
        checksum = 0
        urg_ptr = 0
        
        return struct.pack('!HHLLBBHHH', 
                         src_port, dst_port, seq_num, ack_num, 
                         data_offset, flags, window, checksum, urg_ptr)
                         
    def create_udp_header(self, payload_length):
        # Simplified UDP header
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 1023)
        length = 8 + payload_length  # UDP header + payload
        checksum = 0
        
        return struct.pack('!HHHH', src_port, dst_port, length, checksum)
        
    def create_icmp_header(self):
        # Simplified ICMP echo request header
        type = 8  # Echo request
        code = 0
        checksum = 0
        identifier = random.randint(0, 65535)
        sequence = random.randint(0, 65535)
        
        # Pack without checksum
        header = struct.pack('!BBHHH', type, code, checksum, identifier, sequence)
        
        # Calculate checksum
        checksum = self.calculate_checksum(header)
        
        # Repack with checksum
        return struct.pack('!BBHHH', type, code, checksum, identifier, sequence)
        
    def calculate_checksum(self, data):
        # Simplified checksum calculation
        if len(data) % 2:
            data += b'\x00'
            
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
        
    def update_charts(self):
        if self.traffic_running:
            # Update line chart (traffic over time)
            current_time = time.time() - self.start_time
            self.traffic_data['time'].append(current_time)
            self.traffic_data['volume'].append(self.packets_sent)
            
            self.ax1.clear()
            self.ax1.plot(list(self.traffic_data['time']), list(self.traffic_data['volume']), 'b-')
            self.ax1.set_xlabel('Time (s)')
            self.ax1.set_ylabel('Packets Sent')
            self.ax1.set_title('Traffic Volume Over Time')
            self.ax1.grid(True, color='#CCCCCC')
            self.fig1.tight_layout()
            self.canvas1.draw()
            
            # Update pie chart (protocol distribution)
            self.ax2.clear()
            protocols = list(self.traffic_data['protocols'].keys())
            values = list(self.traffic_data['protocols'].values())
            
            if any(values):
                colors = ['#4682B4', '#5F9EA0', '#87CEEB']
                self.ax2.pie(values, labels=protocols, autopct='%1.1f%%', colors=colors)
                self.ax2.set_title('Protocol Distribution')
            self.fig2.tight_layout()
            self.canvas2.draw()
            
            # Update statistics labels
            self.sent_label.config(text=f"Packets Sent: {self.packets_sent}")
            
            if len(self.traffic_data['time']) > 1:
                time_diff = self.traffic_data['time'][-1] - self.traffic_data['time'][-2]
                if time_diff > 0:
                    rate = (self.traffic_data['volume'][-1] - self.traffic_data['volume'][-2]) / time_diff
                    self.rate_label.config(text=f"Current Rate: {rate:.1f} pps")
            
            elapsed = time.time() - self.start_time
            self.elapsed_label.config(text=f"Elapsed Time: {elapsed:.1f}s")
            
            if self.duration.get() > 0:
                remaining = max(0, self.duration.get() - elapsed)
                self.remaining_label.config(text=f"Remaining: {remaining:.1f}s")
        
        # Schedule next update
        self.root.after(1000, self.update_charts)
        
    # Menu command methods
    def new_project(self):
        messagebox.showinfo("New Project", "Creating new project...")
        
    def open_project(self):
        file_path = filedialog.askopenfilename(
            title="Open Project",
            filetypes=[("Security Project Files", "*.secproj"), ("All Files", "*.*")]
        )
        if file_path:
            messagebox.showinfo("Open Project", f"Opening project: {file_path}")
            
    def save_project(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Project",
            defaultextension=".secproj",
            filetypes=[("Security Project Files", "*.secproj"), ("All Files", "*.*")]
        )
        if file_path:
            messagebox.showinfo("Save Project", f"Saving project to: {file_path}")
            
    def show_dashboard(self):
        messagebox.showinfo("View", "Showing Traffic Dashboard")
        
    def show_packet_analysis(self):
        messagebox.showinfo("View", "Showing Packet Analysis")
        
    def show_network_map(self):
        messagebox.showinfo("View", "Showing Network Map")
        
    def open_port_scanner(self):
        messagebox.showinfo("Tools", "Opening Port Scanner")
        
    def open_packet_sniffer(self):
        messagebox.showinfo("Tools", "Opening Packet Sniffer")
        
    def open_vulnerability_scanner(self):
        messagebox.showinfo("Tools", "Opening Vulnerability Scanner")
        
    def open_traffic_generator(self):
        messagebox.showinfo("Tools", "Opening Traffic Generator")
        
    def open_appearance_settings(self):
        messagebox.showinfo("Settings", "Opening Appearance Settings")
        
    def open_network_settings(self):
        messagebox.showinfo("Settings", "Opening Network Settings")
        
    def open_notification_settings(self):
        messagebox.showinfo("Settings", "Opening Notification Settings")

def main():
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()