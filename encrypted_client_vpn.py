import asyncio
import socket
import struct
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SHARED_KEY = b'ThisIsASecretKeyOf32BytesLength!'
SERVER_ADDRESS = "10.100.102.8"  # Your VPN server IP
SERVER_PORT = 3030

class VPNClient:
    def __init__(self, server_host, server_port, local_port=8080):
        self.server_host = server_host
        self.server_port = server_port
        self.local_port = local_port
        
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

    async def handle_browser_connection(self, reader, writer):
        """Handle incoming connection from browser"""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"Browser connected: {client_addr}")
        
        try:
            # Connect to VPN server
            server_reader, server_writer = await asyncio.open_connection(
                self.server_host, self.server_port
            )
            
            # Read the HTTP request from browser
            request_data = b""
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=1.0)
                    if not chunk:
                        break
                    request_data += chunk
                    
                    # Check if we have a complete HTTP request
                    if b"\r\n\r\n" in request_data:
                        break
                except asyncio.TimeoutError:
                    break
            
            if not request_data:
                return
                
            logger.info(f"Forwarding request: {request_data[:100]}...")
            
            # Encrypt and send to VPN server
            encrypted_request = self.encrypt(request_data)
            
            # Send request header and data
            header = struct.pack('!II', 1, len(encrypted_request))  # Type 1 = HTTP proxy request
            server_writer.write(header + encrypted_request)
            await server_writer.drain()
            
            # Handle the response
            if request_data.startswith(b'CONNECT'):
                # HTTPS tunnel
                await self.handle_tunnel(reader, writer, server_reader, server_writer)
            else:
                # HTTP request
                await self.handle_http_response(writer, server_reader)
                
        except Exception as e:
            logger.error(f"Error handling browser connection: {e}")
        finally:
            # Clean up connections
            writer.close()
            await writer.wait_closed()
            if 'server_writer' in locals():
                server_writer.close()
                await server_writer.wait_closed()

    async def handle_http_response(self, browser_writer, server_reader):
        """Handle HTTP response from server"""
        try:
            # Read response from server
            header = await server_reader.readexactly(8)
            response_type, data_len = struct.unpack('!II', header)
            
            if response_type == 2:  # Response data
                encrypted_response = await server_reader.readexactly(data_len)
                decrypted_response = self.decrypt(encrypted_response)
                
                # Forward to browser
                browser_writer.write(decrypted_response)
                await browser_writer.drain()
                
        except Exception as e:
            logger.error(f"Error handling HTTP response: {e}")

    async def handle_tunnel(self, browser_reader, browser_writer, server_reader, server_writer):
        """Handle HTTPS tunnel (CONNECT method)"""
        try:
            # Wait for the 200 Connection established response
            header = await server_reader.readexactly(8)
            response_type, data_len = struct.unpack('!II', header)
            
            if response_type == 2:  # Response
                encrypted_response = await server_reader.readexactly(data_len)
                decrypted_response = self.decrypt(encrypted_response)
                
                # Send 200 response to browser
                browser_writer.write(decrypted_response)
                await browser_writer.drain()
                
                # Start bidirectional tunneling
                await asyncio.gather(
                    self.tunnel_data(browser_reader, server_writer, encrypt=True),
                    self.tunnel_data_from_server(server_reader, browser_writer),
                    return_exceptions=True
                )
                
        except Exception as e:
            logger.error(f"Error in tunnel: {e}")

    async def tunnel_data(self, reader, writer, encrypt=False):
        """Tunnel data from browser to server"""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                    
                if encrypt:
                    encrypted_data = self.encrypt(data)
                    header = struct.pack('!II', 3, len(encrypted_data))  # Type 3 = tunnel data
                    writer.write(header + encrypted_data)
                else:
                    writer.write(data)
                    
                await writer.drain()
                
        except Exception as e:
            logger.debug(f"Tunnel ended: {e}")

    async def tunnel_data_from_server(self, server_reader, browser_writer):
        """Tunnel data from server to browser"""
        try:
            while True:
                # Read header
                header = await server_reader.readexactly(8)
                msg_type, data_len = struct.unpack('!II', header)
                
                if msg_type == 3:  # Tunnel data
                    encrypted_data = await server_reader.readexactly(data_len)
                    decrypted_data = self.decrypt(encrypted_data)
                    browser_writer.write(decrypted_data)
                    await browser_writer.drain()
                else:
                    break
                    
        except Exception as e:
            logger.debug(f"Server tunnel ended: {e}")

    async def start_proxy(self):
        """Start the local proxy server"""
        server = await asyncio.start_server(
            self.handle_browser_connection,
            '127.0.0.1',
            self.local_port
        )
        
        addr = server.sockets[0].getsockname()
        logger.info(f"VPN client proxy listening on {addr[0]}:{addr[1]}")
        logger.info(f"Configure your browser to use HTTP proxy: 127.0.0.1:{self.local_port}")
        
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    client = VPNClient(SERVER_ADDRESS, SERVER_PORT, local_port=8080)
    
    try:
        asyncio.run(client.start_proxy())
    except KeyboardInterrupt:
        logger.info("Client stopped")
