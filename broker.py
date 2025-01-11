import base64
import time
import os
import random
import subprocess

from scapy.all import sniff, wrpcap, IP
import threading

# consts
mqtt_broker="192.168.100.100"
mqtt_port=1883

config_dir="/home/broker/broker/config/"
ascon_dir = "/home/broker/broker/ascon-c/encrypt/"
hash_dir = "/home/broker/broker/ascon-c/hash/"

#----------------------------------------------------------------------------------------- start sniffing
# Variables to store the captured packets and byte counts
captured_packets = []
sent_bytes = 0
recv_bytes = 0
stop_sniffing = threading.Event()

def packet_callback(packet):
    global sent_bytes, recv_bytes
    if IP in packet:
        if packet[IP].sport == mqtt_port:
            sent_bytes += len(packet)
        elif packet[IP].dport == mqtt_port:
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
#    global sent_bytes, recv_bytes
    stop_sniffing.set()
    print("Sniffing stopped.")

    # Save packets to a pcap file
    OUTPUT_PCAP_FILE = "captured_packets_broker.pcap"  
    wrpcap(OUTPUT_PCAP_FILE, captured_packets)
    print(f"Packets saved to {OUTPUT_PCAP_FILE}")
    print(f"Data sent on port {mqtt_port}: {sent_bytes} bytes ({sent_bytes * 8} bits)")
    print(f"Data received on port {mqtt_port}: {recv_bytes} bytes ({recv_bytes * 8} bits)")
    os.system(f"mosquitto_pub -h {mqtt_broker} -t /test/test123 -p {mqtt_port} -m asdf") # a simple connection to stop sniffing. 

#sniff_thread = start_sniff(mqtt_port)



# read ID_p
with open(f"{config_dir}id_p","r") as f:
        id_p = f.read().replace("\n","")

# read topic
with open(f"{config_dir}topic_i","r") as f:
        topic_i = f.read().replace("\n","")

# read key
with open(f"{config_dir}k_p","r") as f:
        k_p=f.read().replace('\n','')

print("[+] Initial values:")
print(f"\t- ID Subscriber (ID_S) (16 Bytes): {id_p}")
print(f"\t- Topic (Topic_i): {topic_i}")
print(f"\t- Initial Key (K_P) (16 Bytes): {k_p}")

# mqtt connection: receiving M1
try:
	command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {topic_i} -C 1"
	m1_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
	m1=m1_temp.stdout.decode("utf-8").replace("\n","")
	print(f"\n\033[92m[+] M1={{CPp1, Rp, Topic, Tp1}} has been received : {{{m1}}}\033[0m")
except:
        exit()

m1_=m1.split(",")
received_cipher=m1_[0]
received_rp = m1_[1]
received_topic = m1_[2]
received_tag=m1_[3]

# search received topic in DB
with open(f"{config_dir}topic_i","r") as f:
	if received_topic not in f.read():
		print("[-] Wrong Tpoic")
		exit()

# calculate M`1
try:
        encrypted_temp=subprocess.run(
                [
                        f'{ascon_dir}ascon',
                        'enc',
                        id_p, # payload
                        str(len(id_p)), # payload's length
                        k_p, # key
                        str(received_rp), # nonce
                        str(received_topic) # additional data
                ],
                stdout=subprocess.PIPE
        )
        aead=encrypted_temp.stdout.decode('utf-8')
        aead=aead.split("\n")[:-1]
        tag=aead[0][7:]
        cipher=aead[1][7:]
except Exception as e:
	print(e)
	exit()

# compare M1 with M`1
if (cipher != received_cipher) or (tag != received_tag):
	print("[-] Wrong credentials.")
	exit()

# generate random number
rb=random.randint(1_000_000_000,9_999_999_999)

# generate M2
payload = f"{received_rp}{id_p}"
key_ = k_p
nonce_ = str(rb)
ad_ = str(topic_i)
time.sleep(2)
print(f"\n[+] M2 Encryption Details:\n\t- Payload(Rp || IDp): {payload}\n\t- KPi(Initial key): {key_}\n\t- Nonce(Rb): {nonce_}\n\t- AD(Topic_i): {ad_}")
try:
	encrypted_temp=subprocess.run(
	        [
	                f'{ascon_dir}ascon',
	                'enc',
	                payload, # payload
	                str(len(payload)), # payload's length
	                key_, # key
	                nonce_, # nonce
	                ad_ # additional data
	        ],
	        stdout=subprocess.PIPE
	)

	aead=encrypted_temp.stdout.decode('utf-8').split("\n")[:-1]
except Exception as e:
	print(e)
	exit()

cipher = aead[1][7:]
tag = aead[0][7:]
m2=f"{rb},{tag}"
print(f"\033[92m[+] Sending M2={{Rb, Tb}} : {{{m2}}}\033[0m")

# mqtt connection: sending m2
time.sleep(2)
os.system(f"mosquitto_pub -h {mqtt_broker} -p {mqtt_port} -t {topic_i} -m '{m2}' > /dev/null")

# mqtt connection: receiving m3
try:
        command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {topic_i} -C 1"
        m3_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
        m3=m3_temp.stdout.decode("utf-8").replace("\n","")
        print(f"\n\033[92m[+] M3={{Tp2}} has been received : {{{m3}}}\033[0m")
#       print(f"M2 Len: {len(m2)}")
except Exception as e:
        print(e)
        exit()

received_tag = m3

# verify m3
# calculate M3
rb_ = str(rb).encode()
rp_ = str(received_rp).encode()
rb_xor_rp_byte = bytes([x ^ y for x, y in zip(rb_, rp_)])
rb_xor_rp_b64 = base64.b64encode(rb_xor_rp_byte).decode()

topic_i_ = topic_i.encode()
id_p_ = id_p.encode()
topic_xor_idp_byte = bytes([x ^ y for x, y in zip(topic_i_,id_p_ )])
topic_xor_idp_b64 = base64.b64encode(topic_xor_idp_byte).decode()

try:
        payload = f"{topic_xor_idp_b64}"
        encrypted_temp=subprocess.run(
                [
                        f'{ascon_dir}ascon',
                        'enc',
                        payload, # payload
                        str(len(payload)), # payload's length
                        k_p, # key
                        str(rb_xor_rp_b64), # nonce
                        str(topic_i) # additional data
                ],
                stdout=subprocess.PIPE
        )

        aead=encrypted_temp.stdout.decode('utf-8').split("\n")[:-1]
        tag=aead[0][7:]
        cipher=aead[1][7:]

except Exception as e:
        print(e)

if tag != received_tag:
	print("[-] Wrong credentials.")
	exit()

print(f"\n\033[1m[+] Done. SK= {cipher}\033[0m")

# stop sniffing
#stop_sniff()

# timing
#end = time.time()

#with open("temp_time","r") as f:
#	start = float(f.read())
#os.remove("temp_time")

#elapsed_time = (end - start - 1.5 )*1000 # there are three 0.5-second sleep before each pub
#print(f"---------------------------\nElapsed Time (millisec): 119.8878288269043")
#with open("timing","a") as f:
#	f.write(str(elapsed_time)+"\n")

