import json
import sys
import socket
import struct
import time
import base64
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from typing import List, Dict, Optional, Tuple, Any, Callable


# ==============================================================================
# CONSTANTS & CONFIGURATION
# ==============================================================================

class CONSTANTS:
    DEFAULT_PORT = 32108  

    class REQUEST_MESSAGE_TYPE:
        LOCAL_LOOKUP = bytes([0xF1, 0x30])
        CHECK_CAM = bytes([0xF1, 0x41])
        DATA = bytes([0xF1, 0xD0])

    class RESPONSE_MESSAGE_TYPE:
        LOCAL_LOOKUP_RESP = bytes([0xF1, 0x41])
        DATA = bytes([0xF1, 0xD0])

    class P2P_DATA_TYPE_HEADER:
        DATA = bytes([0xD1, 0x00])

    class ENCRYPTION_TYPE:
        NONE = 0
        AES = 1

    MAX_SEQUENCE_NUMBER = 65535
    MAGIC_WORD = "XZYH"


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

class Utils:
    @staticmethod
    def is_p2p_command_encrypted(cmd: int) -> bool:
        return True

    @staticmethod
    def send_message(sock: socket.socket, address: Tuple[str, int], msg_id: bytes,
                    payload: Optional[bytes] = None) -> int:
        if payload is None:
            payload = bytes()

        if msg_id == CONSTANTS.REQUEST_MESSAGE_TYPE.LOCAL_LOOKUP:
            message = msg_id + payload
        else:
            payload_len = struct.pack('!H', len(payload))
            message = msg_id + payload_len + payload

        try:
            bytes_sent = sock.sendto(message, address)
            return bytes_sent
        except Exception as e:
            raise RuntimeError(f'Transmission Failed: {e}') from e

    @staticmethod
    def has_header(msg: bytes, searched_type: bytes) -> bool:
        if len(msg) < 2:
            return False
        return msg[:2] == searched_type

    @staticmethod
    def build_command_header(seq_number: int, command_type: int) -> bytes:
        data_type_buffer = CONSTANTS.P2P_DATA_TYPE_HEADER.DATA
        seq_buffer = struct.pack('!H', seq_number)
        magic_string = CONSTANTS.MAGIC_WORD.encode('utf-8')
        command_type_buffer = struct.pack('<H', command_type)
        return data_type_buffer + seq_buffer + magic_string + command_type_buffer

    @staticmethod
    def build_int_string_command_payload(encryption_type: int, encryption_key: Optional[bytes],
                                        command_type: int, value: int, value_sub: int = 0,
                                        str_value: str = "", str_value_sub: str = "",
                                        channel: int = 0) -> bytes:
        empty_buffer = bytes([0x00, 0x00])
        magic_buffer = bytes([0x01, 0x00])

        encrypted = (Utils.is_p2p_command_encrypted(command_type) and
                    encryption_type != CONSTANTS.ENCRYPTION_TYPE.NONE and
                    encryption_key is not None and len(encryption_key) == 16)

        channel_buffer = bytes([channel, encryption_type if encrypted else 0])
        someint_buffer = struct.pack('<I', value_sub)
        value_buffer = struct.pack('<I', value)

        str_value_buffer = Utils.string_with_length(str_value) if str_value else bytes()
        str_value_sub_buffer = Utils.string_with_length(str_value_sub) if str_value_sub else bytes()

        tmp_data_buffer = someint_buffer + value_buffer + str_value_buffer + str_value_sub_buffer

        if encrypted:
            data_buffer = Utils.padding_p2p_data(tmp_data_buffer)
        else:
            data_buffer = tmp_data_buffer

        header_buffer = struct.pack('<H', len(data_buffer))

        if encrypted:
            encrypted_data = Utils.encrypt_p2p_data(data_buffer, encryption_key)
        else:
            encrypted_data = data_buffer

        return header_buffer + empty_buffer + magic_buffer + channel_buffer + empty_buffer + encrypted_data

    @staticmethod
    def build_string_command_payload(encryption_type: int, encryption_key: Optional[bytes],
                                    command_type: int, str_payload: str, channel: int = 255) -> bytes:
        empty_buffer = bytes([0x00, 0x00])
        magic_buffer = bytes([0x01, 0x00])

        encrypted = (Utils.is_p2p_command_encrypted(command_type) and
                    encryption_type != CONSTANTS.ENCRYPTION_TYPE.NONE and
                    encryption_key is not None and len(encryption_key) == 16)

        channel_buffer = bytes([channel, encryption_type if encrypted else 0])
        payload_buffer = str_payload.encode('utf-8')

        if encrypted:
            data_buffer = Utils.padding_p2p_data(payload_buffer)
        else:
            data_buffer = payload_buffer

        header_buffer = struct.pack('<H', len(data_buffer))

        if encrypted:
            encrypted_data = Utils.encrypt_p2p_data(data_buffer, encryption_key)
        else:
            encrypted_data = data_buffer

        return header_buffer + empty_buffer + magic_buffer + channel_buffer + empty_buffer + encrypted_data

    @staticmethod
    def build_int_command_payload(encryption_type: int, encryption_key: Optional[bytes],
                                 command_type: int, value: int, str_value: str = "",
                                 channel: int = 255) -> bytes:
        empty_buffer = bytes([0x00, 0x00])
        magic_buffer = bytes([0x01, 0x00])

        encrypted = (Utils.is_p2p_command_encrypted(command_type) and
                    encryption_type != CONSTANTS.ENCRYPTION_TYPE.NONE and
                    encryption_key is not None and len(encryption_key) == 16)

        channel_buffer = bytes([channel, encryption_type if encrypted else 0])
        value_buffer = struct.pack('<I', value)

        str_value_buffer = Utils.string_with_length(str_value) if str_value else bytes()

        tmp_data_buffer = value_buffer + str_value_buffer

        if encrypted:
            data_buffer = Utils.padding_p2p_data(tmp_data_buffer)
        else:
            data_buffer = tmp_data_buffer

        header_buffer = struct.pack('<H', len(data_buffer))

        if encrypted:
            encrypted_data = Utils.encrypt_p2p_data(data_buffer, encryption_key)
        else:
            encrypted_data = data_buffer

        return header_buffer + empty_buffer + magic_buffer + channel_buffer + empty_buffer + encrypted_data

    @staticmethod
    def build_void_command_payload(channel: int = 255) -> bytes:
        header_buffer = bytes([0x00, 0x00])
        empty_buffer = bytes([0x00, 0x00])
        magic_buffer = bytes([0x01, 0x00])
        channel_buffer = bytes([channel, 0x00])
        return header_buffer + empty_buffer + magic_buffer + channel_buffer + empty_buffer

    @staticmethod
    def padding_p2p_data(data: bytes, blocksize: int = 16) -> bytes:
        if len(data) < blocksize:
            buffer_size = blocksize
        else:
            buffer_size = (len(data) + blocksize - 1) // blocksize * blocksize

        result = bytearray(buffer_size)
        result[:len(data)] = data
        return bytes(result)

    @staticmethod
    def encrypt_p2p_data(data: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt_p2p_data(data: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data)

    @staticmethod
    def string_with_length(input_str: str, chunk_length: int = 128) -> bytes:
        string_buffer = input_str.encode('utf-8')
        if len(string_buffer) < chunk_length:
            buffer_size = chunk_length
        else:
            buffer_size = (len(string_buffer) + chunk_length - 1) // chunk_length * chunk_length

        result = bytearray(buffer_size)
        result[:len(string_buffer)] = string_buffer
        return bytes(result)

    @staticmethod
    def p2p_did_to_buffer(p2p_did: str) -> bytes:
        p2p_array = p2p_did.split("-")
        buf1 = Utils.string_with_length(p2p_array[0], 8)
        buf2 = struct.pack('!I', int(p2p_array[1]))
        buf3 = Utils.string_with_length(p2p_array[2], 8)
        return buf1 + buf2 + buf3

    @staticmethod
    def build_check_cam_payload(p2p_did: str) -> bytes:
        p2p_did_buffer = Utils.p2p_did_to_buffer(p2p_did)
        magic = bytes([0x00, 0x00, 0x00])
        return p2p_did_buffer + magic

    @staticmethod
    def build_local_lookup_payload() -> bytes:
        return bytes([0x00, 0x00])


# ==============================================================================
# CORE LOGIC
# ==============================================================================

class OfflineP2PSync:
    def __init__(self, station_sn: str, broadcast_address: str = "",
                 encryption_type: int = 0, logger: Optional[Callable[[str], None]] = None):
        self.p2p_did = None
        self.station_sn = station_sn
        self.broadcast_address = broadcast_address
        self.encryption_type = encryption_type
        self.logger = logger or print
        self.encryption_key = self._generate_encryption_key()

        self.socket = None
        self.local_port = None
        self.connected = False
        self.connect_address = None
        self.seq_number = 0

        self.logger('Initializing P2P Client...')

    def _generate_encryption_key(self) -> Optional[bytes]:
        if not self.station_sn:
            return None
        sn_last7 = self.station_sn[-7:].rjust(7, '0')
        return sn_last7.encode('utf-8')

    def bind(self):
        if self.socket is not None:
            return
    
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            self.socket.sendto(b'', ('127.0.0.1', 1))
        except:
            pass

        self.local_port = self.socket.getsockname()[1]

    def discover(self, timeout: int = 3) -> List[Dict[str, Any]]:
        self.bind()

        devices = []
        payload = Utils.build_local_lookup_payload()

        broadcast_addresses = [self.broadcast_address] if self.broadcast_address else ['192.168.0.255']

        self.logger('Starting Device Discovery...')

        for broadcast_address in broadcast_addresses:
            try:
                Utils.send_message(
                    self.socket,
                    (broadcast_address, CONSTANTS.DEFAULT_PORT),
                    CONSTANTS.REQUEST_MESSAGE_TYPE.LOCAL_LOOKUP,
                    payload
                )
            except Exception as e:
                self.logger(f'Error sending broadcast: {e}')

        self.socket.settimeout(timeout / 1000)
        start_time = time.time()

        while time.time() - start_time < timeout / 1000:
            try:
                data, addr = self.socket.recvfrom(4096)
                if Utils.has_header(data, CONSTANTS.RESPONSE_MESSAGE_TYPE.LOCAL_LOOKUP_RESP):
                    if len(data) >= 24:
                        part1 = data[4:12].decode('utf-8').rstrip('\x00')
                        part2 = struct.unpack('!I', data[12:16])[0]
                        part3 = data[16:24].decode('utf-8').rstrip('\x00')
                        p2p_did = f'{part1}-{str(part2).zfill(6)}-{part3}'

                        device = {
                            'host': addr[0],
                            'ip': addr[0],
                            'port': addr[1],
                            'p2pDid': p2p_did
                        }

                        if device not in devices:
                            devices.append(device)

            except socket.timeout:
                continue
            except Exception as e:
                if '10054' in str(e):
                    continue
                else:
                    self.logger(f'Reception Error: {e}')
                    break

        self.logger(f'Discovery Completed, found {len(devices)} devices')
        return devices
    
    def connect(self, device: Dict[str, Any], max_retries: int = 3):
        if self.connected:
            self.logger('[*] Connection Established, no need to reconnect')
            return

        if self.socket is None:
            raise Exception('Socket Initialization Required. Call discover() first.')
        
        self.p2p_did = device['p2pDid']
        self.connect_address = (device['host'], device['port'])
        self._generate_full_encryption_key()

        payload = Utils.build_check_cam_payload(self.p2p_did)
        
        for attempt in range(max_retries):
            try:
                Utils.send_message(
                    self.socket,
                    self.connect_address,
                    CONSTANTS.REQUEST_MESSAGE_TYPE.CHECK_CAM,
                    payload
                )
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    self.logger(f'[-] Failed to send CHECK_CAM to {device["host"]}:{device["port"]}: {e}')
                    raise
                self.logger(f'[*] Retry {attempt + 1}/{max_retries} for {device["host"]}:{device["port"]}')
                time.sleep(0.1)
        
        self._clear_receive_buffer()

        self.connected = True

    def _generate_full_encryption_key(self):
        if not self.station_sn or not self.p2p_did:
            return

        sn_last7 = self.station_sn[-7:].rjust(7, '0')
        dash_index = self.p2p_did.find('-')

        if dash_index >= 0:
            p2p_did_part = self.p2p_did[dash_index:].ljust(9, '0')[:9]
        else:
            p2p_did_part = self.p2p_did.ljust(9, '0')[:9]

        key_string = (sn_last7 + p2p_did_part)[:16]
        self.encryption_key = key_string.encode('utf-8')

    def _clear_receive_buffer(self):
        if not self.socket:
            return

        original_timeout = self.socket.gettimeout()
        self.socket.settimeout(0.01)
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)
        except socket.timeout:
            pass
        except Exception as e:
            pass
        finally:
            self.socket.settimeout(original_timeout)

    def send_command_with_int_string(self, command_type: int, value: int,
                                    value_sub: int = 0, str_value: str = "",
                                    str_value_sub: str = "", channel: int = 0):
        if not self.connected or not self.connect_address:
            raise Exception('Not connected to device')

        command_header = Utils.build_command_header(self.seq_number, command_type)
        payload = Utils.build_int_string_command_payload(
            self.encryption_type,
            self.encryption_key,
            command_type,
            value,
            value_sub,
            str_value,
            str_value_sub,
            channel
        )

        data = command_header + payload

        Utils.send_message(
            self.socket,
            self.connect_address,
            CONSTANTS.REQUEST_MESSAGE_TYPE.DATA,
            data
        )

        self.seq_number = (self.seq_number + 1) % (CONSTANTS.MAX_SEQUENCE_NUMBER + 1)

    def receive_data(self, timeout: int = 3000) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        if not self.connected or not self.socket:
            raise Exception('Not connected to device')

        self.socket.settimeout(timeout / 1000)
        
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)
                if addr == self.connect_address:
                    return data, addr
        except socket.timeout:
            return None
        except Exception as e:
            self.logger(f'Receive Error: {e}')
            return None

    def close(self):
        self.connected = False
        self.connect_address = None
        self.p2p_did = None
        self.seq_number = 0
        self._clear_receive_buffer()

    def shutdown(self):
        if self.socket:
            self.socket.close()
            self.socket = None


# ==============================================================================
# WORKER THREAD LOGIC
# ==============================================================================

def execute_scan(config: Dict[str, Any], log_queue: queue.Queue, result_queue: queue.Queue):
    """
    Executes the P2P scan and RTSP retrieval in a separate thread.
    """
    p2p = None
    try:
        # Create a logger that pushes to the queue
        def log_to_queue(message: str):
            log_queue.put(message)

        p2p = OfflineP2PSync(
            station_sn=config['stationSn'],
            broadcast_address=config['broadcastAddress'],
            encryption_type=config['encryptionType'],
            logger=log_to_queue
        )
        
        devices = p2p.discover(timeout=2000)
        nas_switch = 1
        cameraID = 0
        
        if devices:
            target_ip = config['target']
            matched_device = None
            
            for device in devices:
                if target_ip == device['host']:
                    matched_device = device
                    break
            
            if matched_device:
                p2p.connect(matched_device)  
                p2p.send_command_with_int_string(command_type=1145,
                                                 value=nas_switch,
                                                 value_sub=cameraID,
                                                 str_value=config['accountId'],
                                                 str_value_sub="",
                                                 channel=0)       
                
                received_packets = []
                start_time = time.time()
                timeout = 3
                
                while time.time() - start_time < timeout:
                    result = p2p.receive_data(timeout=500)
                    if result is not None:
                        received_data, addr = result
                        received_packets.append(received_data)
                
                rtsp_url = None
                for received_data in received_packets:
                    if len(received_data) == 152:
                        if(received_data[0] == 0xf1 and received_data[1] == 0xd0 ):
                            rtsp_url = Utils.decrypt_p2p_data(received_data[24:], p2p.encryption_key).decode('utf-8', errors='ignore')
                            if rtsp_url:
                                log_to_queue(f'RTSP URL Retrieved: {rtsp_url}')    
                                break
                
                p2p.close()
                result_queue.put(rtsp_url)
            else:
                log_to_queue(f'No device found matching target IP: {target_ip}')
                result_queue.put(None)
        else:
            log_to_queue('No devices discovered on the network.')
            result_queue.put(None)

    except Exception as error:
        log_to_queue(f'Operation Failed: {error}')
        import traceback
        traceback.print_exc()
        result_queue.put(None)
    finally:
        if p2p:
            p2p.shutdown()


# ==============================================================================
# GUI APPLICATION
# ==============================================================================

class P2PApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Camera Device Scanner & RTSP Fetcher")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        self.log_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.current_rtsp_url = None

        self.setup_ui()
        self.check_queues()

    def setup_ui(self):
        # Main Frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Input Section
        input_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Station SN
        ttk.Label(input_frame, text="Station Serial Number (SN):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_sn = ttk.Entry(input_frame, show="*", width=30)
        self.entry_sn.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)

        # Account ID
        ttk.Label(input_frame, text="Account ID:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_account = ttk.Entry(input_frame, show="*", width=30)
        self.entry_account.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

        # Target IP
        ttk.Label(input_frame, text="Target Device IP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.entry_target = ttk.Entry(input_frame, width=30)
        self.entry_target.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        self.entry_target.insert(0, "192.168.0.100")

        # Broadcast Address
        ttk.Label(input_frame, text="Broadcast Address:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.entry_broadcast = ttk.Entry(input_frame, width=30)
        self.entry_broadcast.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        self.entry_broadcast.insert(0, "192.168.0.255")

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.btn_scan = ttk.Button(btn_frame, text="Scan & Retrieve", command=self.start_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_copy = ttk.Button(btn_frame, text="Copy URL", command=self.copy_url, state=tk.DISABLED)
        self.btn_copy.pack(side=tk.LEFT, padx=5)

        # Result Section
        result_frame = ttk.LabelFrame(main_frame, text="RTSP Stream URL", padding="10")
        result_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        self.lbl_rtsp = ttk.Label(result_frame, text="Waiting for result...", foreground="gray")
        self.lbl_rtsp.pack(side=tk.LEFT, padx=5)

        # Log Section
        log_frame = ttk.LabelFrame(main_frame, text="System Log", padding="10")
        log_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.rowconfigure(3, weight=1)

        self.txt_log = tk.Text(log_frame, height=10, state=tk.DISABLED, wrap=tk.WORD)
        self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.txt_log.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_log.config(yscrollcommand=scrollbar.set)

    def log_message(self, message: str):
        """Thread-safe logging to GUI"""
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.txt_log.see(tk.END)
        self.txt_log.config(state=tk.DISABLED)

    def check_queues(self):
        """Poll queues for log messages and results"""
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_message(msg)
        except queue.Empty:
            pass

        try:
            result = self.result_queue.get_nowait()
            if result:
                self.current_rtsp_url = result
                self.lbl_rtsp.config(text="rtsp://*******", foreground="green")
                self.btn_copy.config(state=tk.NORMAL)
                self.btn_scan.config(state=tk.NORMAL)
            else:
                self.lbl_rtsp.config(text="No URL Retrieved", foreground="red")
                self.btn_scan.config(state=tk.NORMAL)
        except queue.Empty:
            pass

        self.root.after(100, self.check_queues)

    def start_scan(self):
        """Start the scanning process in a background thread"""
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_copy.config(state=tk.DISABLED)
        self.lbl_rtsp.config(text="Scanning...", foreground="gray")
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.delete(1.0, tk.END)
        self.txt_log.config(state=tk.DISABLED)

        config = {
            'stationSn': self.entry_sn.get(),
            'accountId': self.entry_account.get(),
            'target': self.entry_target.get(),
            'broadcastAddress': self.entry_broadcast.get(),
            'encryptionType': CONSTANTS.ENCRYPTION_TYPE.AES
        }

        if not config['stationSn'] or not config['accountId'] or not config['target']:
            messagebox.showerror("Input Error", "Please fill in all required fields.")
            self.btn_scan.config(state=tk.NORMAL)
            return

        thread = threading.Thread(target=execute_scan, args=(config, self.log_queue, self.result_queue), daemon=True)
        thread.start()

    def copy_url(self):
        """Copy the full RTSP URL to clipboard"""
        if self.current_rtsp_url:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_rtsp_url)
            self.root.update()
            messagebox.showinfo("Success", "RTSP URL copied to clipboard.")


if __name__ == '__main__':
    # Ensure dependencies are installed
    # pip install pycryptodome
    root = tk.Tk()
    app = P2PApp(root)
    root.mainloop()
