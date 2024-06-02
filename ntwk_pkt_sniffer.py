import tkinter as tk
import threading
from scapy.all import *

# Global flag to indicate whether sniffing should continue or stop
sniffing = False

def packet_callback(packet):
    if not sniffing:  # Check if sniffing should continue
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload = packet[TCP].payload
        log_text.insert(tk.END, f"TCP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}, protocol: {protocol}, payload: {payload}\n")
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        payload = packet[UDP].payload
        log_text.insert(tk.END, f"UDP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}, protocol: {protocol}, payload: {payload}\n")
    elif ICMP in packet:
        log_text.insert(tk.END, f"ICMP packet from {src_ip} to {dst_ip}, protocol: {protocol}\n")
    else:
        log_text.insert(tk.END, f"Other IP packet from {src_ip} to {dst_ip}, protocol: {protocol}\n")
    log_text.see(tk.END)

def start_sniffing():
    global sniffing
    sniffing = True  # Set sniffing flag to True
    sniff_thread = threading.Thread(target=start_sniffing_thread)
    sniff_thread.daemon = True
    sniff_thread.start()

def start_sniffing_thread():
    sniff(prn=packet_callback, filter="ip")

def stop_sniffing():
    global sniffing
    sniffing = False  # Set sniffing flag to False

# GUI
root = tk.Tk()
root.title("Packet Sniffer")

log_frame = tk.Frame(root)
log_frame.pack(fill=tk.BOTH, expand=True)

log_text = tk.Text(log_frame)
log_text.pack(fill=tk.BOTH, expand=True)

button_frame = tk.Frame(root)
button_frame.pack()

start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=tk.LEFT)

stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(side=tk.LEFT)

root.mainloop()
