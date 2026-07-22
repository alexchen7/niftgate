from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class SourceSpec:
    text: str
    prefix_len: int | None
    kind: str


def normalize_ip(value: str) -> str:
    address = ipaddress.ip_address(value.strip())
    if address.version != 4:
        raise ValueError("only IPv4 addresses are supported")
    return str(address)


def normalize_network(value: str, host_policy: int | None = None) -> SourceSpec:
    raw = value.strip().replace("，", ",")
    if not raw:
        raise ValueError("empty source")
    if "-" in raw:
        start_s, end_s = [x.strip() for x in raw.split("-", 1)]
        start = ipaddress.ip_address(start_s)
        end = ipaddress.ip_address(end_s)
        if start.version != 4 or end.version != 4:
            raise ValueError("only IPv4 ranges are supported")
        if int(start) > int(end):
            raise ValueError("range start is greater than range end")
        return SourceSpec(f"{start}-{end}", None, "range")
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        if net.version != 4:
            raise ValueError("only IPv4 networks are supported")
        return SourceSpec(str(net), net.prefixlen, "cidr")
    ip = ipaddress.ip_address(raw)
    if ip.version != 4:
        raise ValueError("only IPv4 addresses are supported")
    if host_policy == 24:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return SourceSpec(str(net), 24, "cidr")
    return SourceSpec(f"{ip}/32", 32, "cidr")


def normalize_sources(value: str, host_policy: int | None = None) -> list[SourceSpec]:
    specs: list[SourceSpec] = []
    for part in value.replace("，", ",").split(","):
        part = part.strip()
        if part:
            specs.append(normalize_network(part, host_policy))
    return specs


def collapse_sources_for_nft(sources: Iterable[str]) -> list[str]:
    networks: list[ipaddress.IPv4Network] = []
    for source in sources:
        text = source.strip()
        if not text:
            continue
        if "-" in text:
            start_s, end_s = text.split("-", 1)
            start = ipaddress.ip_address(start_s.strip())
            end = ipaddress.ip_address(end_s.strip())
            if start.version != 4 or end.version != 4:
                raise ValueError("only IPv4 ranges are supported")
            networks.extend(ipaddress.summarize_address_range(start, end))
        else:
            network = ipaddress.ip_network(text, strict=False)
            if network.version != 4:
                raise ValueError("only IPv4 networks are supported")
            networks.append(network)
    return [str(network) for network in ipaddress.collapse_addresses(networks)]


def contains_ip(source: str, ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if "-" in source:
        start_s, end_s = source.split("-", 1)
        return int(ipaddress.ip_address(start_s)) <= int(addr) <= int(ipaddress.ip_address(end_s))
    return addr in ipaddress.ip_network(source, strict=False)
