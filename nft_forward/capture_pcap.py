"""Bounded NFLOG PCAP decoding. No packet content is returned in metadata."""
from __future__ import annotations

import ipaddress
import struct

PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)


class Stream:
    def __init__(self):
        self.buffer = bytearray()
        self.endian = None
        self.nano = False

    def feed(self, data):
        self.buffer.extend(data)
        if len(self.buffer) > 2 * 1024 * 1024:
            raise ValueError("capture stream exceeds buffer limit")
        if self.endian is None:
            if len(self.buffer) < 24:
                return
            formats = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
                       b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}
            if bytes(self.buffer[:4]) not in formats:
                raise ValueError("invalid capture stream header")
            self.endian, self.nano = formats[bytes(self.buffer[:4])]
            _, major, minor, _, _, snaplen, link = struct.unpack(self.endian + "IHHIIII", self.buffer[:24])
            if (major, minor) != (2, 4) or link != 239 or not 0 < snaplen <= 1024 * 1024:
                raise ValueError("capture requires NFLOG PCAP format")
            del self.buffer[:24]
        while len(self.buffer) >= 16:
            sec, fraction, size, original = struct.unpack(self.endian + "IIII", self.buffer[:16])
            if size > 1024 * 1024 or size > original or fraction >= (10**9 if self.nano else 10**6):
                raise ValueError("invalid capture record length/time")
            if len(self.buffer) < 16 + size:
                break
            packet = bytes(self.buffer[16:16 + size])
            del self.buffer[:16 + size]
            yield sec, fraction // 1000 if self.nano else fraction, packet


def decode_nflog(data, endian="<"):
    if len(data) < 4 or data[0] != 2 or data[1] != 0:
        return None
    offset, payload, prefix = 4, None, None
    while offset < len(data):
        if offset + 4 > len(data):
            return None
        length, kind = struct.unpack_from(endian + "HH", data, offset)
        if length < 4 or offset + length > len(data):
            return None
        value = data[offset + 4:offset + length]
        if kind == 9:
            payload = value
        elif kind == 10:
            prefix = value.rstrip(b"\0")
        offset += (length + 3) & ~3
    if prefix not in {b"NGCAP:B", b"NGCAP:A"} or payload is None:
        return None
    record = decode_ipv4(payload)
    if record is None:
        return None
    record["scope"] = "blocked" if prefix == b"NGCAP:B" else "all"
    return payload[:record["captured_bytes"]], record


def decode_ipv4(data):
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    header = (data[0] & 15) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    fragment = struct.unpack_from("!H", data, 6)[0]
    if header < 20 or header > len(data) or total < header or fragment & 0x1FFF:
        return None
    protocol = data[9]
    end = min(total, len(data))
    if protocol not in {6, 17} or end < header + (20 if protocol == 6 else 8):
        return None
    source_port, dest_port = struct.unpack_from("!HH", data, header)
    transport = (data[header + 12] >> 4) * 4 if protocol == 6 else 8
    if transport < (20 if protocol == 6 else 8) or header + transport > end:
        return None
    flags = ""
    if protocol == 6:
        flags = ",".join(name for bit, name in enumerate(("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")) if data[header + 13] & (1 << bit))
    return {"source_ip": str(ipaddress.IPv4Address(data[12:16])),
            "destination_ip": str(ipaddress.IPv4Address(data[16:20])),
            "source_port": source_port, "destination_port": dest_port,
            "protocol": "TCP" if protocol == 6 else "UDP", "flags": flags,
            "ttl": data[8], "packet_bytes": total, "captured_bytes": end,
            "payload_bytes": max(0, end - header - transport),
            "truncated": end < total, "fragmented": bool(fragment & 0x2000)}
