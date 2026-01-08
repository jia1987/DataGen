"""IEEE 802.3 Frame Generator

IEEE 802.3 帧数据仿真程序，支持多种上层协议类型。

IEEE 802.3 帧结构:
- Preamble (7 bytes): 10101010 pattern (通常不包含在数据中)
- SFD (1 byte): 10101011 (通常不包含在数据中)
- Destination MAC (6 bytes)
- Source MAC (6 bytes)
- Length (2 bytes): 数据长度 (<=1500)
- LLC Header (3 bytes): DSAP, SSAP, Control
- SNAP Header (5 bytes, 可选): OUI (3 bytes) + Protocol ID (2 bytes)
- Payload (variable)
- Padding (if needed, to reach minimum 46 bytes)
- FCS (4 bytes, 可选)

支持的上层协议:
- IPv4 (via SNAP)
- IPv6 (via SNAP)
- ARP (via SNAP)
- MPLS (via SNAP)
- IPX (native LLC)
- NetBIOS (native LLC)
- Raw LLC

用法示例:
  python 802P3_gen.py --count 10 --payload ipv4 --out frames.pcap
"""

from __future__ import annotations

import argparse
import os
import random
import struct
import time
from enum import Enum
from typing import List, Optional, Tuple, Union

# LLC SAP 值
LLC_SAP_NULL = 0x00
LLC_SAP_SNAP = 0xAA
LLC_SAP_IPX = 0xE0
LLC_SAP_NETBIOS = 0xF0
LLC_SAP_STP = 0x42

# SNAP OUI
SNAP_OUI_STANDARD = b'\x00\x00\x00'

# 以太类型 (用于 SNAP 封装)
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_MPLS_UNI = 0x8847
ETHERTYPE_MPLS_MULTI = 0x8848
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

# IPX 协议类型
IPX_PACKET_TYPE_UNKNOWN = 0
IPX_PACKET_TYPE_RIP = 1
IPX_PACKET_TYPE_ECHO = 2
IPX_PACKET_TYPE_ERROR = 3
IPX_PACKET_TYPE_PEP = 4
IPX_PACKET_TYPE_SPX = 5
IPX_PACKET_TYPE_NCP = 17

PCAP_MAGIC_BE = 0xa1b2c3d4
PCAP_MAGIC_LE = 0xd4c3b2a1


class LLCType(Enum):
    """LLC 帧类型"""
    SNAP = "snap"        # SNAP 封装 (用于 IP, ARP, MPLS 等)
    IPX = "ipx"          # Novell IPX
    NETBIOS = "netbios"  # NetBIOS
    STP = "stp"          # Spanning Tree Protocol
    RAW = "raw"          # 原始 LLC


def mac_str_to_bytes(mac: str) -> bytes:
    """将 MAC 地址字符串转换为 bytes"""
    parts = mac.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("MAC 必须为 6 个字节，例如 00:11:22:33:44:55")
    return bytes(int(p, 16) for p in parts)


def random_mac() -> bytes:
    """生成随机 MAC 地址"""
    return bytes((random.randint(0, 255) for _ in range(6)))


def _ip_checksum(header: bytes) -> int:
    """计算 IPv4 首部校验和"""
    if len(header) % 2 == 1:
        header = header + b'\x00'
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_tcp_header(src_port: int, dst_port: int) -> bytes:
    """构建 TCP 头部 (20 bytes，无选项)"""
    seq_num = random.randint(0, 0xFFFFFFFF)
    ack_num = 0
    data_offset = 5  # 20 bytes / 4 = 5
    flags = 0x02  # SYN
    window = 65535
    checksum = 0  # 简化处理
    urgent = 0
    offset_flags = (data_offset << 12) | flags
    return struct.pack('!HHIIHHHH',
                       src_port, dst_port, seq_num, ack_num,
                       offset_flags, window, checksum, urgent)


def _crc32(data: bytes) -> int:
    """计算 IEEE 802.3 CRC-32 (FCS)"""
    crc = 0xFFFFFFFF
    poly = 0xEDB88320
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def build_llc_header(dsap: int, ssap: int, control: int = 0x03) -> bytes:
    """构建 LLC 头部 (3 bytes)

    Args:
        dsap: Destination Service Access Point
        ssap: Source Service Access Point
        control: Control field (0x03 = Unnumbered Information)
    """
    return struct.pack('!BBB', dsap, ssap, control)


def build_snap_header(oui: bytes, protocol_id: int) -> bytes:
    """构建 SNAP 头部 (5 bytes)

    Args:
        oui: Organizationally Unique Identifier (3 bytes)
        protocol_id: Protocol ID (2 bytes, 通常是以太类型)
    """
    return oui + struct.pack('!H', protocol_id)


def build_ipv4_packet(length: int, extra: Optional[dict] = None) -> bytes:
    """构建 IPv4 数据包"""
    extra = extra or {}
    if length < 40:  # IP头(20) + TCP头(20)
        length = 40
    version_ihl = 0x45
    tos = 0
    total_length = length
    ident = random.randint(0, 65535)
    flags_frag = 0x4000  # Don't Fragment
    ttl = 64
    proto = extra.get('proto', 6)  # 默认 TCP
    src_ip = extra.get('src_ip', bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)]))
    dst_ip = extra.get('dst_ip', bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)]))

    header_no_cksum = struct.pack('!BBHHHBBH4s4s',
                                  version_ihl, tos, total_length, ident, flags_frag,
                                  ttl, proto, 0, src_ip, dst_ip)
    checksum = _ip_checksum(header_no_cksum)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_ihl, tos, total_length, ident, flags_frag,
                            ttl, proto, checksum, src_ip, dst_ip)

    tcp_data_len = max(0, length - 40)
    tcp_header = _build_tcp_header(
        random.randint(1024, 65535),
        random.randint(1, 1023)
    )
    tcp_data = os.urandom(tcp_data_len)
    return ip_header + tcp_header + tcp_data


def build_ipv6_packet(length: int, extra: Optional[dict] = None) -> bytes:
    """构建 IPv6 数据包"""
    extra = extra or {}
    if length < 60:  # IPv6头(40) + TCP头(20)
        length = 60
    payload_len = length - 40
    ver_tc_flow = (6 << 28)
    next_header = extra.get('proto', 6)  # 默认 TCP
    hop_limit = 64
    src = extra.get('src_ip', os.urandom(16))
    dst = extra.get('dst_ip', os.urandom(16))
    ipv6_header = struct.pack('!IHBB16s16s', ver_tc_flow, payload_len, next_header, hop_limit, src, dst)

    tcp_data_len = max(0, payload_len - 20)
    tcp_header = _build_tcp_header(
        random.randint(1024, 65535),
        random.randint(1, 1023)
    )
    tcp_data = os.urandom(tcp_data_len)
    return ipv6_header + tcp_header + tcp_data


def build_arp_packet(length: int, extra: Optional[dict] = None) -> bytes:
    """构建 ARP 数据包"""
    extra = extra or {}
    htype = 1  # Ethernet
    ptype = ETHERTYPE_IPV4
    hlen = 6
    plen = 4
    oper = extra.get('oper', 1)  # 1=request, 2=reply
    sha = extra.get('sha', os.urandom(6))
    spa = extra.get('spa', b'\x0a\x00\x00\x01')
    tha = extra.get('tha', b'\x00' * 6)
    tpa = extra.get('tpa', b'\x0a\x00\x00\x02')
    arp = struct.pack('!HHBBH6s4s6s4s', htype, ptype, hlen, plen, oper, sha, spa, tha, tpa)
    padding_len = max(0, length - len(arp))
    return arp + (b'\x00' * padding_len)


def build_mpls_packet(length: int, extra: Optional[dict] = None) -> bytes:
    """构建 MPLS 数据包"""
    extra = extra or {}
    labels = extra.get('labels', [random.randint(16, (1 << 20) - 1)])  # 避免保留标签 0-15
    mpls_bytes = b''
    for i, lbl in enumerate(labels):
        bos = 1 if i == len(labels) - 1 else 0
        exp = extra.get('exp', 0)  # Traffic Class
        s_ttl = extra.get('ttl', 64)
        entry = ((lbl & 0xFFFFF) << 12) | ((exp & 0x7) << 9) | (bos << 8) | (s_ttl & 0xFF)
        mpls_bytes += struct.pack('!I', entry)

    inner_len = max(0, length - len(mpls_bytes))
    # MPLS 内部通常是 IP 包
    if inner_len >= 40:
        inner_payload = build_ipv4_packet(inner_len)
    else:
        inner_payload = os.urandom(inner_len)
    return mpls_bytes + inner_payload


def build_ipx_packet(length: int, extra: Optional[dict] = None) -> bytes:
    """构建 IPX 数据包"""
    extra = extra or {}
    # IPX 头部 (30 bytes)
    checksum = 0xFFFF  # 无校验和
    packet_length = max(30, length)
    transport_control = 0
    packet_type = extra.get('packet_type', IPX_PACKET_TYPE_NCP)

    dst_network = extra.get('dst_network', os.urandom(4))
    dst_node = extra.get('dst_node', os.urandom(6))
    dst_socket = extra.get('dst_socket', random.randint(0x4000, 0x8000))

    src_network = extra.get('src_network', os.urandom(4))
    src_node = extra.get('src_node', os.urandom(6))
    src_socket = extra.get('src_socket', random.randint(0x4000, 0x8000))

    ipx_header = struct.pack('!HHBB4s6sH4s6sH',
                             checksum, packet_length, transport_control, packet_type,
                             dst_network, dst_node, dst_socket,
                             src_network, src_node, src_socket)

    data_len = max(0, length - 30)
    return ipx_header + os.urandom(data_len)


def build_netbios_packet(length: int, extra: Optional[dict] = None) -> bytes:
    """构建 NetBIOS 数据包 (简化版)"""
    extra = extra or {}
    # NetBIOS 会话服务头部
    msg_type = extra.get('msg_type', 0x00)  # Session Message
    flags = 0x00
    data_len = max(0, length - 4)
    header = struct.pack('!BBH', msg_type, flags, data_len)
    return header + os.urandom(data_len)


def build_stp_bpdu(extra: Optional[dict] = None) -> bytes:
    """构建 STP BPDU (Bridge Protocol Data Unit)"""
    extra = extra or {}
    # IEEE 802.1D STP Configuration BPDU
    protocol_id = 0x0000
    version = 0x00
    bpdu_type = 0x00  # Configuration BPDU
    flags = 0x00
    root_id = extra.get('root_id', b'\x80\x00' + os.urandom(6))
    root_path_cost = extra.get('root_path_cost', 0)
    bridge_id = extra.get('bridge_id', b'\x80\x00' + os.urandom(6))
    port_id = extra.get('port_id', 0x8001)
    message_age = extra.get('message_age', 0)
    max_age = extra.get('max_age', 20 * 256)  # 20 seconds in 1/256 sec
    hello_time = extra.get('hello_time', 2 * 256)  # 2 seconds
    forward_delay = extra.get('forward_delay', 15 * 256)  # 15 seconds

    bpdu = struct.pack('!HBB', protocol_id, version, bpdu_type)
    bpdu += struct.pack('!B', flags)
    bpdu += root_id
    bpdu += struct.pack('!I', root_path_cost)
    bpdu += bridge_id
    bpdu += struct.pack('!H', port_id)
    bpdu += struct.pack('!HHHH', message_age, max_age, hello_time, forward_delay)

    return bpdu


def build_payload(payload_type: str, length: int, extra: Optional[dict] = None) -> Tuple[bytes, bytes, int]:
    """根据类型构造净荷

    返回: (llc_header, snap_header + payload, ethertype)
    """
    extra = extra or {}

    if payload_type == 'ipv4':
        llc = build_llc_header(LLC_SAP_SNAP, LLC_SAP_SNAP, 0x03)
        snap = build_snap_header(SNAP_OUI_STANDARD, ETHERTYPE_IPV4)
        payload = build_ipv4_packet(length, extra)
        return llc, snap + payload, ETHERTYPE_IPV4

    elif payload_type == 'ipv6':
        llc = build_llc_header(LLC_SAP_SNAP, LLC_SAP_SNAP, 0x03)
        snap = build_snap_header(SNAP_OUI_STANDARD, ETHERTYPE_IPV6)
        payload = build_ipv6_packet(length, extra)
        return llc, snap + payload, ETHERTYPE_IPV6

    elif payload_type == 'arp':
        llc = build_llc_header(LLC_SAP_SNAP, LLC_SAP_SNAP, 0x03)
        snap = build_snap_header(SNAP_OUI_STANDARD, ETHERTYPE_ARP)
        payload = build_arp_packet(length, extra)
        return llc, snap + payload, ETHERTYPE_ARP

    elif payload_type == 'mpls':
        llc = build_llc_header(LLC_SAP_SNAP, LLC_SAP_SNAP, 0x03)
        snap = build_snap_header(SNAP_OUI_STANDARD, ETHERTYPE_MPLS_UNI)
        payload = build_mpls_packet(length, extra)
        return llc, snap + payload, ETHERTYPE_MPLS_UNI

    elif payload_type == 'ipx':
        llc = build_llc_header(LLC_SAP_IPX, LLC_SAP_IPX, 0x03)
        payload = build_ipx_packet(length, extra)
        return llc, payload, 0

    elif payload_type == 'netbios':
        llc = build_llc_header(LLC_SAP_NETBIOS, LLC_SAP_NETBIOS, 0x03)
        payload = build_netbios_packet(length, extra)
        return llc, payload, 0

    elif payload_type == 'stp':
        llc = build_llc_header(LLC_SAP_STP, LLC_SAP_STP, 0x03)
        payload = build_stp_bpdu(extra)
        return llc, payload, 0

    else:  # raw
        llc = build_llc_header(LLC_SAP_SNAP, LLC_SAP_SNAP, 0x03)
        snap = build_snap_header(SNAP_OUI_STANDARD, ETHERTYPE_IPV4)
        payload = extra.get('data', os.urandom(length))
        return llc, snap + payload, ETHERTYPE_IPV4


def build_8023_frame(dst_mac: Union[str, bytes], src_mac: Union[str, bytes],
                     payload_type: str = 'ipv4', payload_len: int = 46,
                     vlan: Optional[int] = None, qinq: Optional[int] = None,
                     include_fcs: bool = False,
                     raw_payload: Optional[bytes] = None,
                     extra: Optional[dict] = None) -> bytes:
    """构造完整的 IEEE 802.3 帧

    Args:
        dst_mac: 目标 MAC 地址
        src_mac: 源 MAC 地址
        payload_type: 净荷类型 (ipv4, ipv6, arp, mpls, ipx, netbios, stp, raw)
        payload_len: 净荷长度
        vlan: 802.1Q VLAN ID (可选)
        qinq: QinQ 外层 VLAN ID (可选)
        include_fcs: 是否包含 FCS (4 bytes)
        raw_payload: 原始净荷数据 (可选)
        extra: 额外参数

    Returns:
        完整的 802.3 帧数据
    """
    # 处理 MAC 地址
    if isinstance(dst_mac, str):
        dst = mac_str_to_bytes(dst_mac)
    else:
        dst = bytes(dst_mac) if not isinstance(dst_mac, bytes) else dst_mac
    if isinstance(src_mac, str):
        src = mac_str_to_bytes(src_mac)
    else:
        src = bytes(src_mac) if not isinstance(src_mac, bytes) else src_mac

    extra = extra or {}

    # 构建净荷
    if raw_payload is not None:
        llc = build_llc_header(LLC_SAP_SNAP, LLC_SAP_SNAP, 0x03)
        snap = build_snap_header(SNAP_OUI_STANDARD, ETHERTYPE_IPV4)
        payload_data = llc + snap + raw_payload
    else:
        llc, snap_payload, _ = build_payload(payload_type, payload_len, extra)
        payload_data = llc + snap_payload

    # IEEE 802.3 要求最小数据字段为 46 字节
    # LLC (3) + SNAP (5) + payload = 最小 46 字节
    min_data_len = 46
    if len(payload_data) < min_data_len:
        padding = b'\x00' * (min_data_len - len(payload_data))
        payload_data = payload_data + padding

    # Length 字段 (802.3) - 数据长度不能超过 1500
    length = min(len(payload_data), 1500)

    # 构建帧
    frame = bytearray()
    frame.extend(dst)
    frame.extend(src)

    # 处理 VLAN / QinQ
    if qinq is not None:
        # 外层 VLAN tag (QinQ)
        frame.extend(struct.pack('!H', ETHERTYPE_QINQ))
        frame.extend(struct.pack('!H', qinq & 0xFFF))
        # 内层 VLAN tag
        inner_vlan = vlan if vlan is not None else 0
        frame.extend(struct.pack('!H', ETHERTYPE_VLAN))
        frame.extend(struct.pack('!H', inner_vlan & 0xFFF))
    elif vlan is not None:
        # 单 VLAN tag
        frame.extend(struct.pack('!H', ETHERTYPE_VLAN))
        frame.extend(struct.pack('!H', vlan & 0xFFF))

    # Length 字段
    frame.extend(struct.pack('!H', length))

    # 数据
    frame.extend(payload_data)

    # FCS (可选)
    if include_fcs:
        fcs = _crc32(bytes(frame))
        frame.extend(struct.pack('<I', fcs))  # FCS 使用小端序

    return bytes(frame)


def write_pcap(frames: Union[List[bytes], List[Tuple[int, int, bytes]]], filename: str) -> None:
    """将帧列表写入 pcap 文件

    Args:
        frames: bytes 列表，或 (ts_sec, ts_usec, data) 元组列表
        filename: 输出文件名
    """
    with open(filename, 'wb') as f:
        # PCAP 全局头 (24 bytes)
        global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        f.write(global_header)

        for frame in frames:
            if isinstance(frame, tuple) and len(frame) == 3:
                ts_sec, ts_usec, data = frame
            else:
                now = time.time()
                ts_sec = int(now)
                ts_usec = int((now - ts_sec) * 1_000_000)
                data = frame
            incl_len = len(data)
            orig_len = incl_len
            packet_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(packet_header)
            f.write(data)


def read_pcap(filename: str) -> List[Tuple[int, int, bytes]]:
    """从 pcap 文件读取帧

    Returns:
        (ts_sec, ts_usec, data) 元组列表
    """
    frames = []
    with open(filename, 'rb') as f:
        # 读取全局头
        global_header = f.read(24)
        if len(global_header) < 24:
            return frames

        magic = struct.unpack('<I', global_header[:4])[0]
        if magic == PCAP_MAGIC_LE:
            endian = '<'
        elif magic == PCAP_MAGIC_BE:
            endian = '>'
        else:
            raise ValueError(f"无效的 PCAP 文件: magic=0x{magic:08x}")

        # 读取数据包
        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            frames.append((ts_sec, ts_usec, data))

    return frames


def generate_frames(count: int = 1, payload: str = 'ipv4', payload_len: int = 100,
                    src_mac: Optional[str] = None, dst_mac: Optional[str] = None,
                    vlan: Optional[int] = None, qinq: Optional[int] = None,
                    include_fcs: bool = False,
                    raw_payload: Optional[bytes] = None) -> List[bytes]:
    """生成多个 IEEE 802.3 帧

    Args:
        count: 生成帧数
        payload: 净荷类型
        payload_len: 净荷长度
        src_mac: 源 MAC 地址
        dst_mac: 目标 MAC 地址
        vlan: VLAN ID
        qinq: QinQ 外层 VLAN ID
        include_fcs: 是否包含 FCS
        raw_payload: 原始净荷

    Returns:
        帧数据列表
    """
    frames = []
    src = src_mac or ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6))
    dst = dst_mac or ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6))

    for _ in range(count):
        f = build_8023_frame(dst, src, payload_type=payload, payload_len=payload_len,
                             vlan=vlan, qinq=qinq, include_fcs=include_fcs,
                             raw_payload=raw_payload)
        frames.append(f)
    return frames


def _parse_args():
    p = argparse.ArgumentParser(description='IEEE 802.3 帧生成与 PCAP I/O')
    p.add_argument('--count', '-c', type=int, default=10000, help='生成帧数')
    p.add_argument('--payload', choices=['ipv4', 'ipv6', 'arp', 'mpls', 'ipx', 'netbios', 'stp', 'raw'],
                   default='raw', help='净荷类型')
    p.add_argument('--payload-len', type=int, default=100, help='净荷长度（字节）')
    p.add_argument('--src', type=str, default=None, help='源 MAC 地址，例如 00:11:22:33:44:55')
    p.add_argument('--dst', type=str, default=None, help='目标 MAC 地址')
    p.add_argument('--vlan', type=int, default=None, help='802.1Q VLAN ID (0-4095)')
    p.add_argument('--qinq', type=int, default=None, help='外层 QinQ VLAN ID')
    p.add_argument('--fcs', action='store_true', help='包含 FCS (4 bytes)')
    p.add_argument('--out', type=str, default='802P3.pcap', help='输出 pcap 文件')
    return p.parse_args()


if __name__ == '__main__':
    args = _parse_args()

    print("生成 IEEE 802.3 帧...")
    print(f"  帧数: {args.count}")
    print(f"  净荷类型: {args.payload}")
    print(f"  净荷长度: {args.payload_len}")

    start_time = time.time()
    frames = generate_frames(count=args.count, payload=args.payload, payload_len=args.payload_len,
                             src_mac=args.src, dst_mac=args.dst, vlan=args.vlan, qinq=args.qinq,
                             include_fcs=args.fcs)
    end_time = time.time()

    write_pcap(frames, args.out)

    total_bytes = sum(len(f) for f in frames)
    print(f"已生成 {len(frames)} 帧，共 {total_bytes} 字节")
    print(f"耗时: {end_time - start_time:.2f} 秒")
    print(f"输出文件: {args.out}")