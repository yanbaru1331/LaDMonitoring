import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple
from contextlib import contextmanager


# IPHeader from ping.py
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

    # @staticmethod は以前の修正で削除済み
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


def ip_header_create(
    src_ip: str, dst_ip: str, protocol: int, payload_length: int
) -> IPHeader:
    v_hl = (4 << 4) | 5  # IPv4 and header length of 5 (20 bytes)
    tos = 0  # Type of Service
    total_length = 20 + payload_length  # Header + Payload
    id = 54321  # Identifier
    off = 0  # Fragment offset
    ttl = 64  # Time to Live
    p = protocol  # Protocol (TCP, UDP, etc.)
    sum = 0  # Checksum (to be calculated later)

    return IPHeader(
        v=v_hl >> 4,
        hl=v_hl & 0x0F,
        tos=tos,
        len=total_length,
        id=id,
        off=off,
        ttl=ttl,
        p=p,
        sum=sum,
        src=src_ip,
        dst=dst_ip,
    )


@contextmanager
def raw_socket():
    # IPPROTO_TCPを指定してTCPパケットを扱う
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        yield sock
    finally:
        sock.close()


def tcp_handshake(
    host: str, port: int, timeout: int = 10
) -> Optional[Tuple[IPHeader, TCPHeader, float]]:
    with raw_socket() as sock:
        # Determine the local IP address for the given host
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, port))
            local_ip = "192.168.1.29"

        remote_ip = socket.gethostbyname(host)

        sock.settimeout(timeout)
        # 1. Send SYN
        seq = 12345  # Initial sequence number
        syn_header = TCPHeader(
            src_port=54321,
            dst_port=port,
            seq=seq,
            ack_seq=0,
            data_off=5,
            reserved=0,
            flags=2,  # SYN flag
            window=5840,
            checksum=0,
            urg_ptr=0,
        )
        # Pseudo-header for checksum calculation
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(local_ip),
            socket.inet_aton(remote_ip),
            0,
            socket.IPPROTO_TCP,
            len(syn_header.to_bytes()),
        )
        checksum = calc_checksum(pseudo_header + syn_header.to_bytes())
        syn_header = TCPHeader(
            src_port=54321,
            dst_port=port,
            seq=seq,
            ack_seq=0,
            data_off=5,
            reserved=0,
            flags=2,
            window=5840,
            checksum=checksum,
            urg_ptr=0,
        )
        packet = pseudo_header + syn_header.to_bytes()
        print(
            f"IP Header total_length field (bytes 2-3, should be 0028 for 40 bytes): {packet[2:4].hex()}"
        )
        print(
            f"IP Header checksum field (bytes 10-11, should be 0000 if kernel computes): {packet[10:12].hex()}"
        )

        print(f"IP Header v_hl field (byte 0, should be 45): {packet[0:1].hex()}")
        print(f"remote_ip: {local_ip}, port: {port}")
        sock.sendto(packet, (remote_ip, 0))
        sock.bind((local_ip, 54321))
        send_time = time.time()

        # 2. Receive SYN/ACK
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                print(f"data={data}")
                response_time = time.time()
                ip_header = IPHeader.from_bytes(data[:20])
                tcp_header = TCPHeader.from_bytes(data[20:])

                # --- Debug Print ---
                print(
                    f"Received packet from {ip_header.src}:{tcp_header.src_port} to {ip_header.dst}:{tcp_header.dst_port}, Flags: {tcp_header.flags:03b}"
                )
                # -------------------

                if tcp_header.dst_port == 54321 and tcp_header.flags & 0x12:  # SYN/ACK
                    # 3. Send ACK
                    ack_header = TCPHeader(
                        src_port=54321,
                        dst_port=port,
                        seq=tcp_header.ack_seq,
                        ack_seq=tcp_header.seq + 1,
                        data_off=5,
                        reserved=0,
                        flags=16,  # ACK flag
                        window=5840,
                        checksum=0,
                        urg_ptr=0,
                    )
                    pseudo_header = struct.pack(
                        "!4s4sBBH",
                        socket.inet_aton(local_ip),
                        socket.inet_aton(remote_ip),
                        0,
                        socket.IPPROTO_TCP,
                        len(ack_header.to_bytes()),
                    )
                    checksum = calc_checksum(pseudo_header + ack_header.to_bytes())
                    ack_header = TCPHeader(
                        src_port=54321,
                        dst_port=port,
                        seq=tcp_header.ack_seq,
                        ack_seq=tcp_header.seq + 1,
                        data_off=5,
                        reserved=0,
                        flags=16,
                        window=5840,
                        checksum=checksum,
                        urg_ptr=0,
                    )
                    sock.sendto(ack_header.to_bytes(), (remote_ip, port))
                    rtt = (response_time - send_time) * 1000
                    return (ip_header, tcp_header, rtt)
            except socket.timeout:
                return None, None, None


if __name__ == "__main__":
    host = "localhost"
    port = 80
    result = tcp_handshake(host, port)
    if result:
        ip_header, tcp_header, rtt = result
        print(result)
        print(f"TCP handshake with {host}:{port} successful.")
        print(
            f"Source: {ip_header.src}:{tcp_header.src_port}, Destination: {ip_header.dst}:{tcp_header.dst_port}"
        )
        print(f"RTT: {rtt:.2f} ms")
    else:
        print(f"TCP handshake with {host}:{port} failed or timed out.")

    # この行はTCPハンドシェイクとは直接関係ありませんが、接続試行です。
    # 既存のソケットで生のTCPパケットを送受信しているため、この行は削除するかコメントアウトすることをお勧めします。
    # socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
