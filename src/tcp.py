import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from contextlib import contextmanager
import re

# import subprocess # No longer needed
# from scapy.all import * # No longer needed

import random

LOCALIP = "127.0.0.1"  # This will be determined by the OS
TIMEOUT = 10  # Reduced for practical use
# REMOTEIP = "127.0.0.1" # This will be resolved from host


# IPHeader from ping.py
# This class is not used in the SOCK_STREAM implementation below,
# but is kept for potential compatibility with other files.
@dataclass(frozen=True)
class IPHeader:
    v: int
    hl: int
    tos: int
    len: int
    id: int
    off: int
    ttl: int
    p: int
    sum: int
    src: str  # IPアドレスは文字列として保持
    dst: str  # IPアドレスは文字列として保持

    @staticmethod
    def from_bytes(packed: bytes) -> "IPHeader":
        # unpackではsrcとdstが整数として取得されるため、変数名を変更
        v_hl, tos, len_val, id_val, off_val, ttl, p, sum_val, src_int, dst_int = (
            struct.unpack("!BBHHHBBHII", packed)
        )
        v = v_hl >> 4
        hl = v_hl & 0x0F
        return IPHeader(
            v,
            hl,
            tos,
            len_val,  # 変数名を変更
            id_val,  # 変数名を変更
            off_val,  # 変数名を変更
            ttl,
            p,
            sum_val,  # 変数名を変更
            socket.inet_ntoa(
                src_int.to_bytes(4, byteorder="big")
            ),  # 整数からバイト、そして文字列へ変換
            socket.inet_ntoa(
                dst_int.to_bytes(4, byteorder="big")
            ),  # 整数からバイト、そして文字列へ変換
        )

    def to_bytes(self) -> bytes:
        # IPアドレス文字列をまず4バイトのバイナリデータに変換
        src_packed_bytes = socket.inet_aton(self.src)
        dst_packed_bytes = socket.inet_aton(self.dst)

        # その後、4バイトのバイナリデータを符号なし整数（I）に変換
        src_as_int = struct.unpack("!I", src_packed_bytes)[0]
        dst_as_int = struct.unpack("!I", dst_packed_bytes)[0]

        return struct.pack(
            "!BBHHHBBHII",
            (self.v << 4) | self.hl,
            self.tos,
            self.len,
            self.id,
            self.off,
            self.ttl,
            self.p,
            self.sum,
            src_as_int,  # 整数に変換したものを渡す
            dst_as_int,  # 整数に変換したものを渡す
        )


# This class is not used in the SOCK_STREAM implementation below,
# but is kept for potential compatibility with other files.
@dataclass(frozen=True)
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int
    ack_seq: int
    data_off: int  # 4 bits
    reserved: int  # 3 bits
    flags: int  # 9 bits (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    window: int
    checksum: int
    urg_ptr: int

    def to_bytes(self) -> bytes:
        # data_off is the size of the TCP header in 32-bit words.
        # So, it's 5 for a basic header (20 bytes).
        offset_res_flags = (self.data_off << 12) | (self.reserved << 9) | self.flags
        return struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            offset_res_flags,
            self.window,
            self.checksum,
            self.urg_ptr,
        )

    @classmethod
    def from_bytes(cls, packed: bytes) -> "TCPHeader":
        (
            src_port,
            dst_port,
            seq,
            ack_seq,
            offset_res_flags,
            window,
            checksum,
            urg_ptr,
        ) = struct.unpack("!HHIIHHHH", packed[:20])
        data_off = offset_res_flags >> 12
        reserved = (offset_res_flags >> 9) & 0x7
        flags = offset_res_flags & 0x1FF
        return TCPHeader(
            src_port,
            dst_port,
            seq,
            ack_seq,
            data_off,
            reserved,
            flags,
            window,
            checksum,
            urg_ptr,
        )


# This function is not used in the SOCK_STREAM implementation.
def calc_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    u16_counts = len(data) // 2
    checksum = sum(struct.unpack(f"!{u16_counts}H", data))
    while 0xFFFF < checksum:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    if checksum != 0xFFFF:
        checksum = ~checksum
    return checksum & 0xFFFF


@contextmanager
def stream_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        yield sock
    finally:
        sock.close()


def tcp_com(host: str, port: int, timeout: int = TIMEOUT) -> Optional[bytes]:

    try:
        remote_ip = socket.gethostbyname(host)
        with stream_socket() as sock:
            sock.settimeout(timeout)
            sock.connect((remote_ip, port))

            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            send_time = time.time()
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break  # Connection closed by the server
                response += data
            response_time = time.time()
            rtt = (response_time - send_time) * 1000
            match = re.search(r"HTTP/\d\.\d (\d{3})", response.decode(errors="ignore"))
            return [match.group(1), rtt]

    except socket.timeout:
        print("Socket timed out.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


# mainブロックは、返り値がNoneの場合の処理を修正
if __name__ == "__main__":
    # Note: Connecting to "google.com" on port 80 might result in a redirect (HTTP 301).
    # The response will contain the redirect information.
    host = "www.google.com"
    port = 80
    response_data = tcp_com(host, port)

    if response_data:
        print(response_data)  # Print the HTTP status code
    else:
        print("-" * 30)
        print(f"Failed to get a response from {host}:{port}.")
        print("-" * 30)
