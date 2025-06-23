import asyncio
import socket
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SHARED_KEY = b'ThisIsASecretKeyOf32BytesLength!'

class VPNServer:
    def __init__(self, host='0.0.0.0', port=3030):
        self.host = host
        self.port = port
        self.connections = {}
        
    def encrypt(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, encrypted):
        iv = encrypted[:16]
        cipher = Cipher(algorithms.AES(SHARED_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    async def handle_client(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        logger.info(f"Client connected: {client_addr}")
        
        try:
            while True:
                # Read request header
                header = await reader.readexactly(8)
                request_type, data_len = struct.unpack('!II', header)
                
                if request_type == 1:  # HTTP/HTTPS proxy request
                    await self.handle_proxy_request(reader, writer, data_len)
                elif request_type == 2:  # Raw packet (if needed)
                    await self.handle_raw_packet(reader, writer, data_len)
                else:
                    logger.warning(f"Unknown request type: {request_type}")
                    break
                    
        except asyncio.IncompleteReadError:
            logger.info(f"Client {client_addr} disconnected")
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_proxy_request(self, client_reader, client_writer, data_len):
        try:
            # Read and decrypt the request
            encrypted_data = await client_reader.readexactly(data_len)
            decrypted_data = self.decrypt(encrypted_data)
            
            # Parse the request (simplified - you'd want proper HTTP parsing)
            request_str = decrypted_data.decode('utf-8')
            lines = request_str.split('\r\n')
            first_line = lines[0]
            
            if first_line.startswith('CONNECT'):
                # HTTPS tunnel
                await self.handle_https_tunnel(client_reader, client_writer, first_line)
            else:
                # HTTP request
                await self.handle_http_request(client_reader, client_writer, request_str)
                
        except Exception as e:
            logger.error(f"Error in proxy request: {e}")

    async def handle_https_tunnel(self, client_reader, client_writer, connect_line):
        try:
            # Extract target host and port
            target = connect_line.split()[1]
            host, port = target.split(':')
            port = int(port)
            
            # Connect to target server
            target_reader, target_writer = await asyncio.open_connection(host, port)
            
            # Send 200 Connection established
            response = b"HTTP/1.1 200 Connection established\r\n\r\n"
            encrypted_response = self.encrypt(response)
            
            # Send response header
            header = struct.pack('!II', 2, len(encrypted_response))  # Type 2 = response
            client_writer.write(header + encrypted_response)
            await client_writer.drain()
            
            # Start tunneling
            await asyncio.gather(
                self.tunnel_data(client_reader, target_writer, encrypt=False),
                self.tunnel_data(target_reader, client_writer, encrypt=True)
            )
            
        except Exception as e:
            logger.error(f"Error in HTTPS tunnel: {e}")
        finally:
            if 'target_writer' in locals():
                target_writer.close()
                await target_writer.wait_closed()

    async def handle_http_request(self, client_reader, client_writer, request_str):
        try:
            # Parse HTTP request to extract host
            lines = request_str.split('\r\n')
            host_line = next((line for line in lines if line.lower().startswith('host:')), None)
            
            if not host_line:
                raise ValueError("No Host header found")
                
            host = host_line.split(':', 1)[1].strip()
            
            # Connect to target server
            target_reader, target_writer = await asyncio.open_connection(host, 80)
            
            # Forward request
            target_writer.write(request_str.encode('utf-8'))
            await target_writer.drain()
            
            # Read response
            response_data = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(target_reader.read(8192), timeout=5.0)
                    if not chunk:
                        break
                    response_data += chunk
                except asyncio.TimeoutError:
                    break
            
            # Encrypt and send response
            encrypted_response = self.encrypt(response_data)
            header = struct.pack('!II', 2, len(encrypted_response))
            client_writer.write(header + encrypted_response)
            await client_writer.drain()
            
        except Exception as e:
            logger.error(f"Error in HTTP request: {e}")
        finally:
            if 'target_writer' in locals():
                target_writer.close()
                await target_writer.wait_closed()

    async def tunnel_data(self, reader, writer, encrypt=False):
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                    
                if encrypt:
                    # Encrypt data before sending to client
                    encrypted_data = self.encrypt(data)
                    header = struct.pack('!II', 3, len(encrypted_data))  # Type 3 = tunnel data
                    writer.write(header + encrypted_data)
                else:
                    # Decrypt data from client before sending to target
                    # Note: In a real implementation, you'd need to handle the protocol properly
                    writer.write(data)
                    
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Error in tunnel: {e}")

    async def handle_raw_packet(self, reader, writer, data_len):
        # Your existing packet handling logic, but fixed
        try:
            encrypted_data = await reader.readexactly(data_len)
            # ... handle raw packet forwarding with proper NAT
        except Exception as e:
            logger.error(f"Error handling raw packet: {e}")

    async def start_server(self):
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        addr = server.sockets[0].getsockname()
        logger.info(f"VPN server listening on {addr[0]}:{addr[1]}")
        
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    vpn_server = VPNServer()
    try:
        asyncio.run(vpn_server.start_server())
    except KeyboardInterrupt:
        logger.info("Server stopped")
