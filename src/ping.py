from enum import Enum
from dataclasses import dataclass
from typing import Optional
import socket
from contextlib import contextmanager
from typing import Tuple
import time


import struct


class ICMPType(Enum):
    # 正常系
    ECHOREPLY = 0
    ECHO = 8
    ROUTERE_ADVERT = 9
    ROUTER_SELECTION = 10
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14
    INFORMATION_REQUEST = 15
    INFORMATION_REPLY = 16
    ADDMASK_REQUEST = 17
    ADDMASK_REPLY = 18

    # エラー系
    DESTINATION_UNREACHABLE = 3
    SOUCE_QUENCH = 4
    REDIRECT = 5
    TIME_EXCEEDED = 11
    PARAM_PROBLEM = 12

    def __int__(self):
        return self.value


@dataclass(frozen=True)
class ICMPEcho:
    type: ICMPType
    code: int
    # ここのidを固有にせずにランダムな値としておく
    id: int
    seq: int
    data: bytes
    checksum: Optional[int] = None

    def __post_init__(self):
        if self.checksum is None:
            object.__setattr__(self, "checksum", 0)
            object.__setattr__(self, "checksum", calc_checksum(self.to_bytes()))

    def to_bytes(self) -> bytes:
        return struct.pack(
            f"!BBHHH{len(self.data)}s",
            int(self.type),
            self.code,
            self.checksum,
            self.id,
            self.seq,
            self.data,
        )

    @classmethod
    def from_bytes(cls, packed: bytes) -> "ICMPEcho":
        _type, code, checksum, id, seq = struct.unpack("!BBHHH", packed[:8])
        type = ICMPType(_type)
        data = packed[8:]
        # data = "test"
        return ICMPEcho(type, code, id, seq, data, checksum=checksum)


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
    src: str
    dst: str

    @staticmethod
    def from_bytes(packed: bytes) -> "IPHeader":
        v_hl, tos, len, id, off, ttl, p, sum, src, dst = struct.unpack(
            "!BBHHHBBHII", packed
        )
        v = v_hl >> 4
        hl = v_hl & 0x0F

        return IPHeader(
            v,
            hl,
            tos,
            len,
            id,
            off,
            ttl,
            p,
            sum,
            socket.inet_ntoa(src.to_bytes(4, byteorder="big")),
            socket.inet_ntoa(dst.to_bytes(4, byteorder="big")),
        )


# チェックサムを計算する関数
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
def raw_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        yield sock
    finally:
        sock.close()


def parse_ip_datagram(data: bytes) -> Tuple[IPHeader, bytes]:
    ip_header = IPHeader.from_bytes(data[:20])
    payload = data[20:]
    return (ip_header, payload)


def print_response(ip_header: IPHeader, echo_reply: ICMPEcho) -> None:
    print(
        f"ping echo reply from {ip_header.src}: icmp_seq={echo_reply.seq} ttl={ip_header.ttl}"
    )


def ping(host: str, seq: int, id: int) -> Tuple[IPHeader, ICMPEcho, float]:
    # def ping(host: str, seq: int, id: int) -> None:
    with raw_socket() as sock:
        packet = ICMPEcho(ICMPType.ECHO, 0, id, seq, b"\xff").to_bytes()
        send_time = time.time()
        sock.sendto(packet, (host, 0))
        ip_header, payload = parse_ip_datagram(sock.recvfrom(4096)[0])
        response_time = time.time()
        print(ip_header, payload)
        echo_reply = ICMPEcho.from_bytes(payload)
        # print_response(ip_header, echo_reply)
        rtt = (response_time - send_time) * 1000
        return (ip_header, echo_reply, rtt)
