import threading
import socket
import struct
import pydivert
from collections import deque


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
    padded_data = padder.update(data) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def decrypt(encrypted):
    iv = encrypted[:16]
    cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


SERVER_ADDRESS = "10.100.102.8"
SERVER_PORT = 3030

server_sock = socket.socket()
server_sock.bind((SERVER_ADDRESS, SERVER_PORT))
server_sock.listen()
print("connected to server")

connection_map = {}
map_lock = threading.Lock()

packets_to_send_to_web = deque()
packets_to_web_lock = threading.Lock()



def recv_all(sock , n):
    data = b''
    while len(data) < n:
        part = sock.recv(n- len(data))
        if not part:
            break
        data += part
    return data


def add_to_connection_map(packet , client_sock , client_ip , client_port , interface):
    key = (packet.dst_addr, packet.dst_port)
    with map_lock:
        if key not in connection_map:
            connection_map[key] = (client_sock, client_ip, int(client_port), interface)


def handle_client(client_sock):
    while True:
        metadata_len = struct.unpack("!I", recv_all(client_sock, 4))[0]
        print("reached")

        meta_data = recv_all(client_sock, metadata_len).decode()

        client_ip, client_port, interface_id = meta_data.strip().split(":")
        interface = tuple(map(int, interface_id.strip("()").split(",")))

        raw_packet_len = struct.unpack("!I", recv_all(client_sock, 4))[0]
        packet_raw = recv_all(client_sock, raw_packet_len)

        decrypted_packet_raw = decrypt(packet_raw)
        packet = pydivert.Packet(raw=decrypted_packet_raw, direction=pydivert.Direction.OUTBOUND, interface=(1,0))
        print(packet)
        add_to_connection_map(packet , client_sock , client_ip , client_port , interface)
        with packets_to_web_lock:
            packets_to_send_to_web.append(packet)

def send_packets_to_web():
    with pydivert.WinDivert("false") as w:
        while True:
            with packets_to_web_lock:
                if packets_to_send_to_web:
                    print("len" , len(packets_to_send_to_web))
                    packet = packets_to_send_to_web.popleft()
                    w.send(packet)
                    print(packet)
                    print("packet sent to web")


def sniff_responses_from_web(): #this function also send the packets back to the client
    filter_str = f"inbound and ip and (tcp or udp)"
    seen_packets = set()
    with pydivert.WinDivert(filter_str) as w:
        while True:
            packet_from_web = w.recv()
            fingerprint = (
                packet_from_web.src_addr,
                packet_from_web.src_port,
                packet_from_web.dst_addr,
                packet_from_web.dst_port,
                packet_from_web.tcp.seq_num if packet_from_web.tcp else 0,
                len(packet_from_web.payload),
            )

            if fingerprint in seen_packets:
                continue
            seen_packets.add(fingerprint)
            if len(seen_packets) > 10000:
                seen_packets.clear()

            key = (packet_from_web.src_addr, packet_from_web.src_port)
            with map_lock:
                entry = connection_map.get(key)
                #print(entry)
                if entry:
                    print("recieved packet from web" , packet_from_web)
                    client_sock, client_ip, client_port, interface_id = entry
                    packet_from_web.interface = interface_id
                    packet_from_web.dst_addr = client_ip
                    packet_from_web.dst_port = client_port
                    packet_from_web.recalculate_checksums()
                    print("sending back to the client" , packet_from_web)
                    encrypted_packet = encrypt(bytes(packet_from_web.raw))
                    client_sock.sendall(struct.pack("!I", len(encrypted_packet)) + encrypted_packet)
                else:
                    w.send(packet_from_web)


def main():
    t1 = threading.Thread(target=send_packets_to_web, daemon=True).start()
    t2 = threading.Thread(target=sniff_responses_from_web , daemon=True).start()
    while True:
        client_conn, addr = server_sock.accept()

        print("Client connected:", addr)
        #handle_client(client_conn)
        threading.Thread(target=handle_client, args=(client_conn,), daemon=True).start()


main()