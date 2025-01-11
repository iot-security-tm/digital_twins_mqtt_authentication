from scapy.all import sniff, wrpcap, IP
import os
import threading

# Variables to store the captured packets and byte counts
captured_packets = []
sent_bytes = 0
recv_bytes = 0
stop_sniffing = threading.Event()

def packet_callback(packet):
    global sent_bytes, recv_bytes
    if IP in packet:
        if packet[IP].sport == YOUR_PORT_NUMBER:
            sent_bytes += len(packet)
        elif packet[IP].dport == YOUR_PORT_NUMBER:
            recv_bytes += len(packet)
        captured_packets.append(packet)

def start_sniff(port):
    def sniff_packets():
        print(f"Starting to sniff on port {port}...")
        sniff(filter=f"port {port}", prn=packet_callback, store=0, stop_filter=lambda x: stop_sniffing.is_set())
    
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()
    return sniff_thread

def stop_sniff():
    stop_sniffing.set()
    print("Sniffing stopped.")

    # Save packets to a pcap file
    OUTPUT_PCAP_FILE = "captured_packets.pcap"  
    wrpcap(OUTPUT_PCAP_FILE, captured_packets)
    print(f"Packets saved to {OUTPUT_PCAP_FILE}")
    print(f"Data sent on port {YOUR_PORT_NUMBER}: {sent_bytes} bytes ({sent_bytes * 8} bits)")
    print(f"Data received on port {YOUR_PORT_NUMBER}: {recv_bytes} bytes ({recv_bytes * 8} bits)")
    os.system("mosquitto_pub -h test.mosquitto.org -t /test/test123 -p 1883 -m asdf") # a simple connection to stop sniffing. 



