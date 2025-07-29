from enum import Enum
from dataclasses import dataclass
from typing import Optional
import socket
from contextlib import contextmanager
from typing import Tuple
import time


import struct

TTL = 128


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
    # ここのidを固有にせずにランダムな値
    id: int
    seq: int
    data: bytes
    checksum: Optional[int] = None

    # チェックサムを計算する関数
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


def ping(
    host: str, seq: int, id: int, timeout: int = 5
) -> Optional[Tuple[IPHeader, ICMPEcho, float]]:
    with raw_socket() as sock:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)
        # パケットの作成
        packet = ICMPEcho(ICMPType.ECHO, 0, id, seq, b"\xff").to_bytes()
        # パケットを送信
        sock.sendto(packet, (host, 0))
        send_time = time.time()
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                response_time = time.time()

                ip_header, payload = parse_ip_datagram(data)
                echo_reply = ICMPEcho.from_bytes(payload)
                if echo_reply.id == id:
                    if echo_reply.type == ICMPType.ECHOREPLY:
                        rtt = (response_time - send_time) * 1000
                        return (ip_header, echo_reply, rtt)
                # elif (
                #     echo_reply.type == ICMPType.DESTINATION_UNREACHABLE
                #     or echo_reply.type == ICMPType.TIME_EXCEEDED
                # ):
                #     checkid, _ = parse_ip_datagram(echo_reply.data)
                #     if checkid.id == id:
                #         rtt = (response_time - send_time) * 1000
                #         print("Destination unreachable or time exceeded")

                #         return (ip_header, echo_reply, rtt)

            except socket.timeout:
                print("Ping timed out")
                return None, None, None


if __name__ == "__main__":
    # Example usage
    host = "127.0.0.1"
    seq = 1
    id = 1
    while True:
        i, e, r = ping(host, seq, id)
        print("s")
        time.sleep(1)
    # if (i or e or r) is None:
    #     print(i, e, r)
    #     print("Ping failed or timed out")
    # else:
    #     print(i, e, r)
