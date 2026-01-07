"""GFP (Generic Framing Procedure) 帧生成器

基于 ITU-T G.7041/Y.1303 标准实现

功能:
- 支持 GFP-F (Frame-Mapped) 帧映射模式
- 支持 GFP-T (Transparent-Mapped) 透明映射模式
- 支持多种客户信号类型: Ethernet, PPP, IP, MPLS, Fibre Channel, FICON, ESCON 等
- 支持线性扩展头 (Linear Extension Header)
- 支持 payload FCS (可选)
- 导出为二进制文件或 pcap 文件

GFP 帧结构 (G.7041):
+------------------+
| Core Header (4B) |  PLI (2B) + cHEC (2B)
+------------------+
| Payload Header   |  Type (4B) + tHEC (2B) [+ Extension Header]
+------------------+
| Payload Area     |  Client Data
+------------------+
| Payload FCS (4B) |  可选
+------------------+

用法示例:
  python GFP_gen.py --count 10 --client ethernet --out gfp_frames.bin
  python GFP_gen.py --count 5 --client ppp --mode gfp-t --out gfp_frames.bin

"""

from __future__ import annotations

import argparse
import os
import random
import struct
import time
from typing import List, Tuple

# =============================================================================
# GFP 常量定义 (ITU-T G.7041)
# =============================================================================

# GFP 帧类型 (PTI - Payload Type Identifier, 3 bits)
GFP_PTI_CLIENT_DATA = 0b000        # 客户数据帧 (Client Data Frame)
GFP_PTI_CLIENT_MGMT = 0b100        # 客户管理帧 (Client Management Frame)

# GFP 净荷 FCS 指示 (PFI - Payload FCS Indicator, 1 bit)
GFP_PFI_NO_FCS = 0                 # 无 FCS
GFP_PFI_FCS_PRESENT = 1            # 有 FCS

# GFP 扩展头指示 (EXI - Extension Header Identifier, 4 bits)
GFP_EXI_NULL = 0x0                 # 无扩展头 (Null Extension Header)
GFP_EXI_LINEAR = 0x1               # 线性扩展头 (Linear Extension Header)
GFP_EXI_RING = 0x2                 # 环形扩展头 (Ring Extension Header) - 保留

# GFP 用户净荷标识 (UPI - User Payload Identifier, 8 bits)
# 根据 ITU-T G.7041 Table 6-3
# NULL Extension Header (EXI=0) 的 UPI 值定义:
GFP_UPI_FRAME_MAPPED_ETHERNET = 0x01        # Frame-Mapped Ethernet
GFP_UPI_FRAME_MAPPED_PPP = 0x02             # Frame-Mapped PPP
GFP_UPI_TRANSPARENT_FIBRE_CHANNEL = 0x03    # Transparent Fibre Channel
GFP_UPI_TRANSPARENT_FICON = 0x04            # Transparent FICON
GFP_UPI_TRANSPARENT_ESCON = 0x05            # Transparent ESCON
GFP_UPI_TRANSPARENT_GB_ETHERNET = 0x06      # Transparent Gb Ethernet
GFP_UPI_FRAME_MAPPED_MAPOS = 0x08           # Frame-Mapped MAPOS
GFP_UPI_TRANSPARENT_DVB_ASI = 0x09          # Transparent DVB ASI
GFP_UPI_TRANSPARENT_IEEE_1394 = 0x0A        # Transparent IEEE 1394
GFP_UPI_FRAME_MAPPED_HDLC_SDL = 0x0B        # Frame-Mapped HDLC/SDL
GFP_UPI_FRAME_MAPPED_RPR = 0x0C             # Frame-Mapped RPR
GFP_UPI_FRAME_MAPPED_MPLS_UNICAST = 0x0D    # Frame-Mapped MPLS (Unicast)
GFP_UPI_FRAME_MAPPED_MPLS_MULTICAST = 0x0E  # Frame-Mapped MPLS (Multicast)
GFP_UPI_FRAME_MAPPED_ISIS = 0x0F            # Frame-Mapped IS-IS
GFP_UPI_FRAME_MAPPED_IPV4 = 0x10            # Frame-Mapped IPv4
GFP_UPI_FRAME_MAPPED_IPV6 = 0x11            # Frame-Mapped IPv6
GFP_UPI_FRAME_MAPPED_IPX = 0x12             # Frame-Mapped IPX
GFP_UPI_TRANSPARENT_64B_66B = 0x13          # Transparent 64B/66B encoded client

# 客户类型到 UPI 的映射
CLIENT_TO_UPI = {
    'ethernet': GFP_UPI_FRAME_MAPPED_ETHERNET,
    'ppp': GFP_UPI_FRAME_MAPPED_PPP,
    'ipv4': GFP_UPI_FRAME_MAPPED_IPV4,
    'ipv6': GFP_UPI_FRAME_MAPPED_IPV6,
    'mpls': GFP_UPI_FRAME_MAPPED_MPLS_UNICAST,
    'mpls-multicast': GFP_UPI_FRAME_MAPPED_MPLS_MULTICAST,
    'fc': GFP_UPI_TRANSPARENT_FIBRE_CHANNEL,
    'ficon': GFP_UPI_TRANSPARENT_FICON,
    'escon': GFP_UPI_TRANSPARENT_ESCON,
    'mapos': GFP_UPI_FRAME_MAPPED_MAPOS,
    'isis': GFP_UPI_FRAME_MAPPED_ISIS,
    'ipx': GFP_UPI_FRAME_MAPPED_IPX,
    'hdlc': GFP_UPI_FRAME_MAPPED_HDLC_SDL,
}

# GFP Idle 帧 PLI 值
GFP_IDLE_PLI = 0x0000

# =============================================================================
# CRC 计算函数
# =============================================================================


def _make_crc16_table() -> List[int]:
    """生成 CRC-16 查找表 (用于 cHEC 和 tHEC)

    GFP 使用 CRC-16，生成多项式: x^16 + x^12 + x^5 + 1 (0x1021)
    按照 ITU-T G.7041 标准，使用 MSB-first 方式
    """
    poly = 0x1021
    table = []
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFFFF
        table.append(crc)
    return table


CRC16_TABLE = _make_crc16_table()


def crc16(data: bytes) -> int:
    """计算 CRC-16 (用于 GFP cHEC 和 tHEC)

    根据 ITU-T G.7041:
    - 多项式: x^16 + x^12 + x^5 + 1 (0x1021)
    - 初始值: 0x0000
    - 无最终异或
    """
    crc = 0x0000
    for byte in data:
        crc = ((crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ byte) & 0xFF]) & 0xFFFF
    return crc


def _make_crc32_table() -> List[int]:
    """生成 CRC-32 查找表 (用于 payload FCS)

    IEEE 802.3 CRC-32，生成多项式: 0x04C11DB7 (反转后 0xEDB88320)
    """
    poly = 0xEDB88320
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        table.append(crc)
    return table


CRC32_TABLE = _make_crc32_table()


def crc32(data: bytes) -> int:
    """计算 CRC-32 (用于 GFP payload FCS)"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# =============================================================================
# GFP 核心头 (Core Header) 处理
# =============================================================================

def build_core_header(pli: int) -> bytes:
    """构建 GFP 核心头 (4 字节)

    Core Header 结构:
    - PLI (Payload Length Indicator): 2 bytes - 净荷区域长度
    - cHEC (Core Header Error Control): 2 bytes - CRC-16

    Args:
        pli: 净荷长度指示符 (0-65535)

    Returns:
        4 字节的核心头
    """
    pli_bytes = struct.pack('!H', pli)
    chec = crc16(pli_bytes)
    return pli_bytes + struct.pack('!H', chec)


def verify_core_header(header: bytes) -> Tuple[bool, int]:
    """验证并解析 GFP 核心头

    Args:
        header: 4 字节的核心头

    Returns:
        (is_valid, pli) 元组
    """
    if len(header) < 4:
        return False, 0
    pli = struct.unpack('!H', header[:2])[0]
    chec = struct.unpack('!H', header[2:4])[0]
    expected_chec = crc16(header[:2])
    return chec == expected_chec, pli


# =============================================================================
# GFP 净荷头 (Payload Header) 处理
# =============================================================================

def build_type_field(pti: int, pfi: int, exi: int, upi: int) -> bytes:
    """构建 GFP Type 字段 (2 字节)

    Type 字段结构 (16 bits):
    - PTI (Payload Type Identifier): 3 bits
    - PFI (Payload FCS Indicator): 1 bit
    - EXI (Extension Header Identifier): 4 bits
    - UPI (User Payload Identifier): 8 bits

    Args:
        pti: 净荷类型标识 (0-7)
        pfi: FCS 指示符 (0-1)
        exi: 扩展头标识 (0-15)
        upi: 用户净荷标识 (0-255)

    Returns:
        2 字节的 Type 字段
    """
    type_high = ((pti & 0x07) << 5) | ((pfi & 0x01) << 4) | (exi & 0x0F)
    return bytes([type_high, upi & 0xFF])


def build_payload_header(pti: int, pfi: int, exi: int, upi: int,
                         cid: int = 0, spare: int = 0) -> bytes:
    """构建 GFP 净荷头

    Payload Header 结构:
    - Type (2 bytes): PTI + PFI + EXI + UPI
    - tHEC (2 bytes): Type 字段的 CRC-16
    - Extension Header (可选，取决于 EXI)

    对于 Linear Extension Header (EXI=1):
    - CID (Channel ID): 8 bits
    - Spare: 4 bits
    - eHEC: 4 bits (简化校验)

    Args:
        pti: 净荷类型标识
        pfi: FCS 指示符
        exi: 扩展头标识
        upi: 用户净荷标识
        cid: 通道 ID (用于 Linear Extension Header)
        spare: 保留字段

    Returns:
        净荷头字节串
    """
    type_field = build_type_field(pti, pfi, exi, upi)
    thec = crc16(type_field)
    payload_header = type_field + struct.pack('!H', thec)

    # 添加扩展头
    if exi == GFP_EXI_LINEAR:
        # Linear Extension Header: CID (8 bits) + Spare (4 bits) + eHEC (4 bits)
        ext_data = (cid & 0xFF) << 8 | ((spare & 0x0F) << 4)
        # 简化的 eHEC 计算 (取 CID 的低 4 位异或)
        ehec = (cid ^ (cid >> 4)) & 0x0F
        ext_data |= ehec
        payload_header += struct.pack('!H', ext_data)

    return payload_header


def parse_type_field(type_bytes: bytes) -> Tuple[int, int, int, int]:
    """解析 GFP Type 字段

    Args:
        type_bytes: 2 字节的 Type 字段

    Returns:
        (pti, pfi, exi, upi) 元组
    """
    type_high = type_bytes[0]
    upi = type_bytes[1]
    pti = (type_high >> 5) & 0x07
    pfi = (type_high >> 4) & 0x01
    exi = type_high & 0x0F
    return pti, pfi, exi, upi


# =============================================================================
# 客户数据生成
# =============================================================================

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


def generate_ethernet_payload(length: int) -> bytes:
    """生成 Ethernet 客户数据

    生成简化的 Ethernet 帧 (不含前导码和 FCS)
    内部包含有效的 IPv4 数据包，确保 Wireshark 能正确解析
    """
    if length < 14:
        length = 14  # 最小以太网头

    dst_mac = os.urandom(6)
    src_mac = os.urandom(6)
    ethertype = struct.pack('!H', 0x0800)  # IPv4
    eth_header = dst_mac + src_mac + ethertype

    # 生成有效的 IPv4 数据包作为 Ethernet 净荷
    ip_payload_len = max(0, length - 14)
    if ip_payload_len >= 20:
        # 生成有效的 IPv4 头
        ip_data_len = ip_payload_len - 20
        version_ihl = 0x45  # IPv4, IHL=5 (20 bytes)
        tos = 0
        total_length = ip_payload_len  # IP 总长度
        ident = random.randint(0, 65535)
        flags_frag = 0x4000  # Don't Fragment
        ttl = 64
        proto = 6  # TCP
        src_ip = bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)])
        dst_ip = bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)])
        # 先用 checksum=0 构建头部，再计算校验和
        ip_header_no_cksum = struct.pack('!BBHHHBBH4s4s',
                                         version_ihl, tos, total_length, ident, flags_frag,
                                         ttl, proto, 0, src_ip, dst_ip)
        checksum = _ip_checksum(ip_header_no_cksum)
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                version_ihl, tos, total_length, ident, flags_frag,
                                ttl, proto, checksum, src_ip, dst_ip)
        ip_data = os.urandom(ip_data_len)
        ip_packet = ip_header + ip_data
    else:
        # 长度不够放 IPv4 头，使用原始数据
        ip_packet = os.urandom(ip_payload_len)

    return eth_header + ip_packet


def generate_ppp_payload(length: int) -> bytes:
    """生成 PPP 客户数据

    PPP 帧格式: Protocol (2B) + Information
    """
    if length < 2:
        length = 2
    # PPP 协议字段: 0x0021 = IP
    protocol = struct.pack('!H', 0x0021)
    information = os.urandom(max(0, length - 2))
    return protocol + information


def generate_ipv4_payload(length: int) -> bytes:
    """生成 IPv4 数据包"""
    if length < 20:
        length = 20
    version_ihl = 0x45
    tos = 0
    total_length = length
    ident = random.randint(0, 65535)
    flags_frag = 0
    ttl = 64
    proto = 6  # TCP
    checksum = 0
    src_ip = bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)])
    dst_ip = bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)])
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_length, ident, flags_frag,
                         ttl, proto, checksum, src_ip, dst_ip)
    data = os.urandom(max(0, length - 20))
    return header + data


def generate_ipv6_payload(length: int) -> bytes:
    """生成 IPv6 数据包"""
    if length < 40:
        length = 40
    ver_tc_flow = (6 << 28)  # version = 6
    payload_len = max(0, length - 40)
    next_header = 6  # TCP
    hop_limit = 64
    src_ip = os.urandom(16)
    dst_ip = os.urandom(16)
    header = struct.pack('!IHBB16s16s',
                         ver_tc_flow, payload_len, next_header, hop_limit,
                         src_ip, dst_ip)
    data = os.urandom(payload_len)
    return header + data


def generate_mpls_payload(length: int, label_count: int = 1) -> bytes:
    """生成 MPLS 数据包"""
    mpls_stack = b''
    for i in range(label_count):
        label = random.randint(16, (1 << 20) - 1)  # 16+ 是用户标签
        tc = 0
        bos = 1 if i == label_count - 1 else 0
        ttl = 64
        entry = ((label & 0xFFFFF) << 12) | ((tc & 0x07) << 9) | ((bos & 0x01) << 8) | (ttl & 0xFF)
        mpls_stack += struct.pack('!I', entry)

    remaining = max(0, length - len(mpls_stack))
    # MPLS 下层通常是 IP
    if remaining >= 20:
        inner = generate_ipv4_payload(remaining)
    else:
        inner = os.urandom(remaining)
    return mpls_stack + inner


def generate_fc_payload(length: int) -> bytes:
    """生成 Fibre Channel 客户数据 (用于 GFP-T)

    FC 帧结构简化: SOF (4B) + Header (24B) + Payload + EOF (4B)
    这里生成简化的数据块
    """
    # Fibre Channel 8B/10B 编码后的透明数据
    # 这里简化为随机数据
    return os.urandom(length)


def generate_hdlc_payload(length: int) -> bytes:
    """生成 HDLC 帧数据

    HDLC 帧: Flag + Address + Control + Information + FCS + Flag
    简化生成 (不含标志字节)
    """
    if length < 4:
        length = 4
    address = bytes([0xFF])  # 广播地址
    control = bytes([0x03])  # UI (Unnumbered Information)
    information = os.urandom(max(0, length - 2))
    return address + control + information


def generate_client_payload(client_type: str, length: int) -> bytes:
    """根据客户类型生成净荷数据

    Args:
        client_type: 客户类型 (ethernet, ppp, ipv4, ipv6, mpls, fc, hdlc, raw)
        length: 净荷长度

    Returns:
        客户数据字节串
    """
    generators = {
        'ethernet': generate_ethernet_payload,
        'ppp': generate_ppp_payload,
        'ipv4': generate_ipv4_payload,
        'ipv6': generate_ipv6_payload,
        'mpls': generate_mpls_payload,
        'fc': generate_fc_payload,
        'ficon': generate_fc_payload,
        'escon': generate_fc_payload,
        'hdlc': generate_hdlc_payload,
    }

    generator = generators.get(client_type.lower())
    if generator:
        return generator(length)
    else:
        # 默认: 随机数据
        return os.urandom(length)


# =============================================================================
# GFP 帧构建
# =============================================================================

def build_gfp_frame(client_data: bytes,
                    client_type: str = 'ethernet',
                    mode: str = 'gfp-f',  # noqa: ARG001 - 保留用于未来 GFP-T 扩展
                    include_fcs: bool = False,
                    cid: int = 0,
                    use_extension_header: bool = False) -> bytes:
    """构建完整的 GFP 帧

    Args:
        client_data: 客户数据
        client_type: 客户类型 (ethernet, ppp, ipv4, ipv6, mpls, fc 等)
        mode: GFP 模式 ('gfp-f' 帧映射 或 'gfp-t' 透明映射)
        include_fcs: 是否包含 payload FCS
        cid: 通道 ID (用于扩展头)
        use_extension_header: 是否使用线性扩展头

    Returns:
        完整的 GFP 帧
    """
    # 确定 UPI
    upi = CLIENT_TO_UPI.get(client_type.lower(), GFP_UPI_FRAME_MAPPED_ETHERNET)

    # 确定 PTI
    pti = GFP_PTI_CLIENT_DATA

    # 确定 PFI
    pfi = GFP_PFI_FCS_PRESENT if include_fcs else GFP_PFI_NO_FCS

    # 确定 EXI
    exi = GFP_EXI_LINEAR if use_extension_header else GFP_EXI_NULL

    # 构建净荷头
    payload_header = build_payload_header(pti, pfi, exi, upi, cid=cid)

    # 构建净荷区域 (Payload Header + Client Data)
    payload_area = payload_header + client_data

    # 添加 payload FCS (可选)
    if include_fcs:
        payload_fcs = crc32(payload_area)
        payload_area += struct.pack('!I', payload_fcs)

    # 计算 PLI (净荷区域长度)
    pli = len(payload_area)

    # 构建核心头
    core_header = build_core_header(pli)

    return core_header + payload_area


def build_gfp_idle_frame() -> bytes:
    """构建 GFP Idle 帧

    Idle 帧用于在没有客户数据时保持同步
    PLI = 0, 后跟 cHEC
    """
    return build_core_header(GFP_IDLE_PLI)


def build_gfp_management_frame(mgmt_data: bytes,
                               cid: int = 0,
                               use_extension_header: bool = False) -> bytes:
    """构建 GFP 客户管理帧

    Args:
        mgmt_data: 管理数据
        cid: 通道 ID
        use_extension_header: 是否使用扩展头

    Returns:
        GFP 管理帧
    """
    pti = GFP_PTI_CLIENT_MGMT
    pfi = GFP_PFI_NO_FCS
    exi = GFP_EXI_LINEAR if use_extension_header else GFP_EXI_NULL
    upi = 0x00  # 管理帧 UPI

    payload_header = build_payload_header(pti, pfi, exi, upi, cid=cid)
    payload_area = payload_header + mgmt_data
    pli = len(payload_area)
    core_header = build_core_header(pli)

    return core_header + payload_area


# =============================================================================
# GFP 帧解析
# =============================================================================

def parse_gfp_frame(frame: bytes) -> dict:
    """解析 GFP 帧

    Args:
        frame: GFP 帧字节串

    Returns:
        解析结果字典
    """
    result = {
        'valid': False,
        'is_idle': False,
        'pli': 0,
        'pti': 0,
        'pfi': 0,
        'exi': 0,
        'upi': 0,
        'client_data': b'',
        'fcs_valid': None,
    }

    if len(frame) < 4:
        return result

    # 解析核心头
    core_valid, pli = verify_core_header(frame[:4])
    if not core_valid:
        return result

    result['pli'] = pli

    # 检查是否为 Idle 帧
    if pli == 0:
        result['valid'] = True
        result['is_idle'] = True
        return result

    # 检查帧长度
    if len(frame) < 4 + pli:
        return result

    payload_area = frame[4:4 + pli]

    # 解析 Type 字段
    if len(payload_area) < 4:
        return result

    pti, pfi, exi, upi = parse_type_field(payload_area[:2])
    result['pti'] = pti
    result['pfi'] = pfi
    result['exi'] = exi
    result['upi'] = upi

    # 验证 tHEC
    thec = struct.unpack('!H', payload_area[2:4])[0]
    expected_thec = crc16(payload_area[:2])
    if thec != expected_thec:
        return result

    # 计算净荷头长度
    payload_header_len = 4  # Type (2) + tHEC (2)
    if exi == GFP_EXI_LINEAR:
        payload_header_len += 2  # Extension Header

    # 提取客户数据
    if pfi == GFP_PFI_FCS_PRESENT:
        # 有 FCS，最后 4 字节是 FCS
        client_data = payload_area[payload_header_len:-4]
        payload_fcs = struct.unpack('!I', payload_area[-4:])[0]
        expected_fcs = crc32(payload_area[:-4])
        result['fcs_valid'] = payload_fcs == expected_fcs
    else:
        client_data = payload_area[payload_header_len:]

    result['client_data'] = client_data
    result['valid'] = True

    return result


# =============================================================================
# 帧生成与 I/O
# =============================================================================

def generate_gfp_frames(count: int = 1,
                        client_type: str = 'ethernet',
                        payload_len: int = 100,
                        mode: str = 'gfp-f',
                        include_fcs: bool = False,
                        use_extension_header: bool = False,
                        include_idle_ratio: float = 0.0) -> List[bytes]:
    """批量生成 GFP 帧

    Args:
        count: 生成帧数
        client_type: 客户类型
        payload_len: 客户数据长度
        mode: GFP 模式
        include_fcs: 是否包含 FCS
        use_extension_header: 是否使用扩展头
        include_idle_ratio: Idle 帧比例 (0.0-1.0)

    Returns:
        GFP 帧列表
    """
    frames = []
    for i in range(count):
        if include_idle_ratio > 0 and random.random() < include_idle_ratio:
            # 生成 Idle 帧
            frames.append(build_gfp_idle_frame())
        else:
            # 生成客户数据帧
            client_data = generate_client_payload(client_type, payload_len)
            frame = build_gfp_frame(
                client_data,
                client_type=client_type,
                mode=mode,
                include_fcs=include_fcs,
                cid=i % 256,
                use_extension_header=use_extension_header
            )
            frames.append(frame)
    return frames


def write_gfp_binary(frames: List[bytes], filename: str) -> None:
    """将 GFP 帧写入二进制文件

    文件格式: 连续的 GFP 帧，每帧前有 2 字节长度字段
    """
    with open(filename, 'wb') as f:
        for frame in frames:
            # 写入帧长度 (2 bytes, big-endian)
            f.write(struct.pack('!H', len(frame)))
            f.write(frame)


def read_gfp_binary(filename: str) -> List[bytes]:
    """从二进制文件读取 GFP 帧"""
    frames = []
    with open(filename, 'rb') as f:
        while True:
            len_bytes = f.read(2)
            if not len_bytes or len(len_bytes) < 2:
                break
            frame_len = struct.unpack('!H', len_bytes)[0]
            frame = f.read(frame_len)
            if len(frame) < frame_len:
                break
            frames.append(frame)
    return frames


def write_gfp_pcap(frames: List[bytes], filename: str, wrap_ethernet: bool = False) -> None:
    """将 GFP 帧写入 pcap 文件

    Args:
        frames: GFP 帧列表
        filename: 输出文件名
        wrap_ethernet: 是否将 GFP 帧封装在 Ethernet 帧中 (默认 False，直接输出 GFP 帧)
    """
    # linktype=147 (DLT_USER0) 用于 GFP 帧，linktype=1 用于 Ethernet 封装
    linktype = 1 if wrap_ethernet else 147

    with open(filename, 'wb') as f:
        # 写入 pcap 全局头
        global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
        f.write(global_header)

        for frame in frames:
            now = time.time()
            ts_sec = int(now)
            ts_usec = int((now - ts_sec) * 1_000_000)

            if wrap_ethernet:
                # 将 GFP 帧封装在 Ethernet 帧中
                # 使用自定义 EtherType 0x8915 (用于实验/私有协议)
                dst_mac = b'\x00\x00\x00\x00\x00\x01'  # 目标 MAC
                src_mac = b'\x00\x00\x00\x00\x00\x02'  # 源 MAC
                ethertype = struct.pack('!H', 0x8915)  # 私有 EtherType
                eth_frame = dst_mac + src_mac + ethertype + frame
                data = eth_frame
            else:
                data = frame

            incl_len = len(data)
            orig_len = incl_len
            packet_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(packet_header)
            f.write(data)


# =============================================================================
# 辅助函数
# =============================================================================

def get_upi_name(upi: int) -> str:
    """获取 UPI 对应的名称"""
    upi_names = {
        GFP_UPI_FRAME_MAPPED_ETHERNET: 'Ethernet (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_PPP: 'PPP (Frame-Mapped)',
        GFP_UPI_TRANSPARENT_FIBRE_CHANNEL: 'Fibre Channel (Transparent)',
        GFP_UPI_TRANSPARENT_FICON: 'FICON (Transparent)',
        GFP_UPI_TRANSPARENT_ESCON: 'ESCON (Transparent)',
        GFP_UPI_TRANSPARENT_GB_ETHERNET: 'Gb Ethernet (Transparent)',
        GFP_UPI_FRAME_MAPPED_MAPOS: 'MAPOS (Frame-Mapped)',
        GFP_UPI_TRANSPARENT_DVB_ASI: 'DVB ASI (Transparent)',
        GFP_UPI_TRANSPARENT_IEEE_1394: 'IEEE 1394 (Transparent)',
        GFP_UPI_FRAME_MAPPED_HDLC_SDL: 'HDLC/SDL (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_RPR: 'RPR (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_MPLS_UNICAST: 'MPLS Unicast (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_MPLS_MULTICAST: 'MPLS Multicast (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_ISIS: 'IS-IS (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_IPV4: 'IPv4 (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_IPV6: 'IPv6 (Frame-Mapped)',
        GFP_UPI_FRAME_MAPPED_IPX: 'IPX (Frame-Mapped)',
        GFP_UPI_TRANSPARENT_64B_66B: '64B/66B (Transparent)',
    }
    return upi_names.get(upi, f'Unknown (0x{upi:02X})')


def print_frame_info(frame: bytes, index: int = 0) -> None:
    """打印 GFP 帧信息"""
    result = parse_gfp_frame(frame)

    print(f"=== GFP Frame #{index} ===")
    print(f"  Total Length: {len(frame)} bytes")
    print(f"  Valid: {result['valid']}")

    if result['is_idle']:
        print("  Type: Idle Frame")
        return

    print(f"  PLI: {result['pli']}")
    print(f"  PTI: {result['pti']} ({'Client Data' if result['pti'] == 0 else 'Client Management'})")
    print(f"  PFI: {result['pfi']} ({'FCS Present' if result['pfi'] else 'No FCS'})")
    print(f"  EXI: {result['exi']} ({'Null' if result['exi'] == 0 else 'Linear' if result['exi'] == 1 else 'Other'})")
    print(f"  UPI: 0x{result['upi']:02X} ({get_upi_name(result['upi'])})")
    print(f"  Client Data Length: {len(result['client_data'])} bytes")
    if result['fcs_valid'] is not None:
        print(f"  FCS Valid: {result['fcs_valid']}")


# =============================================================================
# 命令行接口
# =============================================================================

def _parse_args():
    p = argparse.ArgumentParser(
        description='GFP (Generic Framing Procedure) 帧生成器 - ITU-T G.7041',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s --count 10 --client ethernet --out gfp_frames.bin
  %(prog)s --count 5 --client ipv4 --fcs --out gfp_with_fcs.bin
  %(prog)s --count 100 --client ppp --ext-header --out gfp_ext.bin
  %(prog)s --in gfp_frames.bin --info
        '''
    )

    p.add_argument('--count', '-c', type=int, default=10000,
                   help='生成帧数 (默认: 10000)')
    p.add_argument('--client', '-t', type=str, default='ethernet',
                   choices=['ethernet', 'ppp', 'ipv4', 'ipv6', 'mpls', 'fc', 'ficon', 'escon', 'hdlc', 'raw'],
                   help='客户数据类型 (默认: ethernet)')
    p.add_argument('--payload-len', '-l', type=int, default=100,
                   help='客户数据长度 (默认: 100)')
    p.add_argument('--mode', '-m', type=str, default='gfp-f',
                   choices=['gfp-f', 'gfp-t'],
                   help='GFP 模式 (默认: gfp-f)')
    p.add_argument('--fcs', action='store_true',
                   help='包含 payload FCS')
    p.add_argument('--ext-header', action='store_true',
                   help='使用线性扩展头')
    p.add_argument('--idle-ratio', type=float, default=0.0,
                   help='Idle 帧比例 (0.0-1.0, 默认: 0.0)')
    p.add_argument('--out', '-o', type=str, default='gfp_frames.pcap',
                   help='输出文件 (默认: gfp_frames.pcap)')
    p.add_argument('--format', '-f', type=str, default='pcap',
                   choices=['bin', 'pcap'],
                   help='输出格式 (默认: pcap)')
    p.add_argument('--in', dest='infile', type=str, default=None,
                   help='从文件读取 GFP 帧')
    p.add_argument('--info', action='store_true',
                   help='显示帧详细信息')

    return p.parse_args()


if __name__ == '__main__':
    args = _parse_args()

    if args.infile:
        # 读取并显示帧信息
        frames = read_gfp_binary(args.infile)
        print(f'从 {args.infile} 读取到 {len(frames)} 个 GFP 帧')
        if args.info:
            for i, frame in enumerate(frames):
                print_frame_info(frame, i)
                print()
    else:
        # 生成 GFP 帧
        frames = generate_gfp_frames(
            count=args.count,
            client_type=args.client,
            payload_len=args.payload_len,
            mode=args.mode,
            include_fcs=args.fcs,
            use_extension_header=args.ext_header,
            include_idle_ratio=args.idle_ratio
        )

        if args.format == 'pcap':
            write_gfp_pcap(frames, args.out)
        else:
            write_gfp_binary(frames, args.out)

        print(f'已生成 {len(frames)} 个 GFP 帧并写入 {args.out}')

        # 显示第一帧信息作为示例
        if frames and args.info:
            print('\n第一帧信息:')
            print_frame_info(frames[0], 0)
