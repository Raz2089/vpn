import socket
import threading
import time

import pydivert
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives import padding


SHARED_KEY = b'ThisIsASecretKeyOf32BytesLength!'
print(len(SHARED_KEY))
def encrypt(data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

def decrypt(encrypted):
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data

SERVER_ADDRESS = "10.100.102.8"
SERVER_PORT = 3030

client_sock = socket.socket()
client_sock.connect((SERVER_ADDRESS, SERVER_PORT))
print("Connected to server")



def recv_all(sock , n):
    data = b''
    while len(data) < n:
        part = sock.recv(n- len(data))
        if not part:
            break
        data += part
    return data


def send_packet(client_sock , meta_data , packet_raw):
    metadata_len = struct.pack('!I', len(meta_data))
    packet_len = struct.pack('!I', len(packet_raw))
    client_sock.sendall(metadata_len + meta_data + packet_len + packet_raw)


def collect_data_from_server(): #also reinject back to packet buffer
    with pydivert.WinDivert("false") as w:
        while True:
            packet_len = struct.unpack("!I", recv_all(client_sock , 4))[0]
            data_from_server = recv_all(client_sock, packet_len)
            decrypted = decrypt(data_from_server)
            packet_from_server = pydivert.Packet(raw=decrypted, direction=pydivert.Direction.INBOUND, interface=(6, 0))
            print("recieved back from my server")
            w.send(packet_from_server)

def collect_packets_from_user():
    f = f"outbound and ip and ((tcp and (ip.DstAddr != {SERVER_ADDRESS} or tcp.DstPort != {SERVER_PORT})) or (udp and (ip.DstAddr != {SERVER_ADDRESS} or udp.DstPort != {SERVER_PORT})))"
    with pydivert.WinDivert(f) as w:
        while True:
            packet = w.recv()
            print("sending packet to server")
            client_ip = packet.src_addr
            client_port = packet.src_port

            packet.src_addr = SERVER_ADDRESS
            packet.src_port = SERVER_PORT

            packet.recalculate_checksums()
            meta_data = f"{client_ip}:{client_port}:{packet.interface}".encode()
            encrypted_packet = encrypt(bytes(packet.raw))
            send_packet(client_sock, meta_data, encrypted_packet)
            print("sent this packet" , packet)


def main():
    t1 = threading.Thread(target=collect_packets_from_user).start()
    t2 = threading.Thread(target=collect_data_from_server , daemon=True).start()



if __name__ == "__main__":
    main()