import base64
import os
import subprocess
import random
import time

# timing
start=time.time()


# consts
mqtt_broker="192.168.100.100"
mqtt_port="1883"

config_dir="/home/subscriber/subscriber/config/"
ascon_dir = "/home/subscriber/subscriber/ascon-c/encrypt/"
hash_dir = "/home/subscriber/subscriber/ascon-c/hash/"

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
print(f"\t- ID Subcriber (ID_S) (16 Bytes): {id_p}")
print(f"\t- Topic (Topic_i): {topic_i}")
print(f"\t- Initial Key (K_P) (16 Bytes): {k_p}\n")

# generate payload (Rn || Topi || (Sub|Pub|Revoc))
rp=random.randint(1_000_000_000,9_999_999_999)

#encryption
payload = f"{id_p}"
key_ = k_p
nonce_ = str(rp)
ad_ = str(topic_i)
time.sleep(2)
print(f"[+] M1 Encryption Details:\n\t- Payload(IDp): {payload}\n\t- KPi(Initial key): {key_}\n\t- Nonce(Rp): {nonce_}\n\t- AD(Topic_i): {ad_}")
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
	aead=encrypted_temp.stdout.decode('utf-8')
	aead=aead.split("\n")[:-1]
	tag=aead[0][7:]
	cipher=aead[1][7:]
except:
	exit()
m1=f"{cipher},{rp},{topic_i},{tag}"

print(f"\033[92m[+] Sending M1={{CPp1, Rp, Topic, Tp1}} : {{{m1}}}\033[0m")
#print(f"Len M1:{len(m1)}")

# mqtt connection: sending m1
time.sleep(2)
os.system(f"mosquitto_pub -h {mqtt_broker} -p {mqtt_port} -t {topic_i} -m '{m1}' > /dev/null")

# mqtt connection: receiving m2
try:
	command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {topic_i} -C 1"
	m2_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
	m2=m2_temp.stdout.decode("utf-8").replace("\n","")
	print(f"\n\033[92m[+] M2={{Rb, Tb}} has been received : {{{m2}}}\033[0m")
#	print(f"M2 Len: {len(m2)}")
except Exception as e:
	print(e)
	exit()

m2_=m2.split(",")
received_rb=m2_[0]
received_tag = m2_[1]

# verify CPb1
try:
	payload = f"{rp}{id_p}"
	encrypted_temp=subprocess.run(
                [
                        f'{ascon_dir}ascon',
                        'enc',
                        payload, # payload
                        str(len(payload)), # payload's length
                        k_p, # key
                        str(received_rb), # nonce
                        str(topic_i) # additional data
                ],
                stdout=subprocess.PIPE
	)

	aead=encrypted_temp.stdout.decode('utf-8').split("\n")[:-1]
	tag=aead[0][7:]
	cipher=aead[1][7:]

except Exception as e:
        print(e)
        exit()

if tag != received_tag:
	print("[-] Wrong Tag.")
	exit()

# generate M3
rb_ = str(received_rb).encode()
rp_ = str(rp).encode()
rb_xor_rp_byte = bytes([x ^ y for x, y in zip(rb_, rp_)])
rb_xor_rp_b64 = base64.b64encode(rb_xor_rp_byte).decode()

topic_i_ = topic_i.encode()
id_p_ = id_p.encode()
topic_xor_idp_byte = bytes([x ^ y for x, y in zip(topic_i_,id_p_ )])
topic_xor_idp_b64 = base64.b64encode(topic_xor_idp_byte).decode()

payload = f"{topic_xor_idp_b64}"
key_ = k_p
nonce_ = str(rb_xor_rp_b64)
ad_ = topic_i
time.sleep(2)
print(f"\n[+] M3 Encryption Details:\n\t- Payload(Topic XOR IDp): {payload}\n\t- KPi(Initial key): {key_}\n\t- Nonce(Rb XOR Rp): {nonce_}\n\t- AD(Topic_i): {ad_}")
try:
        payload = f"{topic_xor_idp_b64}"
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
        tag=aead[0][7:]
        cipher=aead[1][7:]

except Exception as e:
        print(e)

session_key = cipher
m3 = f"{tag}"
print(f"\033[92m[+] Sending M3={{Tp2}} : {m3}\033[0m")

# mqtt connection: sending m3
time.sleep(2)
os.system(f"mosquitto_pub -h {mqtt_broker} -p {mqtt_port} -t {topic_i} -m '{m3}' > /dev/null")

print(f"\n\033[1m[+] Done. SK= {session_key}\033[0m")
