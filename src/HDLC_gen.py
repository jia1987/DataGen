"""HDLC (High-Level Data Link Control) 帧生成器

基于 ISO 13239 和 Cisco HDLC 标准实现

功能:
- 支持标准 HDLC 帧格式 (ISO HDLC)
- 支持 Cisco HDLC 帧格式
- 支持多种上层协议封装: IPv4, IPv6, MPLS, CLNS 等
- 支持 I 帧、S 帧、U 帧
- 支持 16 位和 32 位 FCS
- 导出为 pcap 文件

标准 HDLC 帧结构:
+----------+----------+----------+-------------+----------+----------+
|   Flag   | Address  | Control  |    Info     |   FCS    |   Flag   |
|  (0x7E)  |  (1-2B)  | (1-2B)   | (Variable)  | (2-4B)   |  (0x7E)  |
+----------+----------+----------+-------------+----------+----------+

Cisco HDLC 帧结构:
+----------+----------+----------+----------+-------------+----------+----------+
|   Flag   | Address  | Control  | Protocol |    Info     |   FCS    |   Flag   |
|  (0x7E)  |  (1B)    |  (1B)    |  (2B)    | (Variable)  | (2-4B)   |  (0x7E)  |
+----------+----------+----------+----------+-------------+----------+----------+

用法示例:
  python HDLC_gen.py --count 10 --protocol ipv4 --out hdlc_frames.pcap
  python HDLC_gen.py --count 5 --cisco --protocol ipv6 --out cisco_hdlc.pcap

"""

from __future__ import annotations

import argparse
import os
import random
import struct
import time
from typing import List

# =============================================================================
# HDLC 常量定义
# =============================================================================

# HDLC 标志字节
HDLC_FLAG = 0x7E

# 标准 HDLC 地址
HDLC_ADDR_ALL_STATIONS = 0xFF     # 全站地址
HDLC_ADDR_NO_STATION = 0x00       # 无站地址
HDLC_ADDR_COMMAND = 0x03          # 命令地址
HDLC_ADDR_RESPONSE = 0x01         # 响应地址

# Cisco HDLC 地址
CISCO_HDLC_ADDR_UNICAST = 0x0F    # 单播地址
CISCO_HDLC_ADDR_BROADCAST = 0x8F  # 广播地址

# 标准 HDLC 控制字段
HDLC_CTRL_UI = 0x03               # Unnumbered Information (UI)
HDLC_CTRL_SABM = 0x2F             # Set Asynchronous Balanced Mode
HDLC_CTRL_SABME = 0x6F            # SABM Extended
HDLC_CTRL_DISC = 0x43             # Disconnect
HDLC_CTRL_UA = 0x63               # Unnumbered Acknowledgment
HDLC_CTRL_DM = 0x0F               # Disconnected Mode
HDLC_CTRL_FRMR = 0x87             # Frame Reject
HDLC_CTRL_XID = 0xAF              # Exchange Identification
HDLC_CTRL_TEST = 0xE3             # Test

# Cisco HDLC 协议类型
CISCO_PROTO_IPV4 = 0x0800            # IPv4
CISCO_PROTO_IPV6 = 0x86DD            # IPv6
CISCO_PROTO_MPLS_UNICAST = 0x8847    # MPLS Unicast
CISCO_PROTO_MPLS_MULTICAST = 0x8848  # MPLS Multicast
CISCO_PROTO_CDP = 0x2000             # Cisco Discovery Protocol
CISCO_PROTO_CLNS = 0xFEFE            # CLNS (ISO)
CISCO_PROTO_SLARP = 0x8035           # SLARP (Serial Line ARP)
CISCO_PROTO_DDP = 0x809B             # AppleTalk DDP
CISCO_PROTO_AARP = 0x80F3            # AppleTalk AARP
CISCO_PROTO_IPX = 0x8137             # Novell IPX
# 协议名称映射
CISCO_PROTOCOL_MAP = {
    'ipv4': CISCO_PROTO_IPV4,
    'ipv6': CISCO_PROTO_IPV6,
    'mpls': CISCO_PROTO_MPLS_UNICAST,
    'mpls-multicast': CISCO_PROTO_MPLS_MULTICAST,
    'cdp': CISCO_PROTO_CDP,
    'clns': CISCO_PROTO_CLNS,
    'slarp': CISCO_PROTO_SLARP,
    'ipx': CISCO_PROTO_IPX,
}

# HDLC 帧类型
HDLC_FRAME_I = 'I'    # Information frame
HDLC_FRAME_S = 'S'    # Supervisory frame
HDLC_FRAME_U = 'U'    # Unnumbered frame

# =============================================================================
# CRC 计算函数
# =============================================================================


def _make_crc16_table() -> List[int]:
    """生成 CRC-16-CCITT 查找表 (用于 HDLC FCS)

    多项式: x^16 + x^12 + x^5 + 1 (0x8408, 反转形式)
    """
    poly = 0x8408
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


CRC16_TABLE = _make_crc16_table()


def crc16_fcs(data: bytes) -> int:
    """计算 HDLC FCS-16

    初始值: 0xFFFF
    最终异或: 0xFFFF
    """
    crc = 0xFFFF
    for byte in data:
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFF


def _make_crc32_table() -> List[int]:
    """生成 CRC-32 查找表 (用于 HDLC FCS-32)

    多项式: 0x04C11DB7 (反转后 0xEDB88320)
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


def crc32_fcs(data: bytes) -> int:
    """计算 HDLC FCS-32"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# =============================================================================
# IP 校验和计算
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


# =============================================================================
# 客户数据生成
# =============================================================================

def _build_tcp_header(src_port: int, dst_port: int) -> bytes:
    """构建 TCP 头部 (20 bytes，无选项)"""
    seq_num = random.randint(0, 0xFFFFFFFF)
    ack_num = 0
    data_offset = 5  # 20 bytes / 4 = 5
    flags = 0x02  # SYN
    window = 65535
    checksum = 0
    urgent = 0
    offset_flags = (data_offset << 12) | flags
    return struct.pack('!HHIIHHHH',
                       src_port, dst_port, seq_num, ack_num,
                       offset_flags, window, checksum, urgent)


def generate_ipv4_payload(length: int) -> bytes:
    """生成 IPv4 数据包"""
    if length < 40:  # IP头(20) + TCP头(20)
        length = 40
    version_ihl = 0x45
    tos = 0
    total_length = length
    ident = random.randint(0, 65535)
    flags_frag = 0x4000  # Don't Fragment
    ttl = 64
    proto = 6  # TCP
    src_ip = bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)])
    dst_ip = bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)])
    # 计算校验和
    header_no_cksum = struct.pack('!BBHHHBBH4s4s',
                                  version_ihl, tos, total_length, ident, flags_frag,
                                  ttl, proto, 0, src_ip, dst_ip)
    checksum = _ip_checksum(header_no_cksum)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_ihl, tos, total_length, ident, flags_frag,
                            ttl, proto, checksum, src_ip, dst_ip)
    # TCP 头
    tcp_header = _build_tcp_header(random.randint(1024, 65535), random.randint(1, 1023))
    tcp_data = os.urandom(max(0, length - 40))
    return ip_header + tcp_header + tcp_data


def generate_ipv6_payload(length: int) -> bytes:
    """生成 IPv6 数据包"""
    if length < 60:  # IPv6头(40) + TCP头(20)
        length = 60
    payload_len = length - 40
    ver_tc_flow = (6 << 28)
    next_header = 6  # TCP
    hop_limit = 64
    src = os.urandom(16)
    dst = os.urandom(16)
    ipv6_header = struct.pack('!IHBB16s16s', ver_tc_flow, payload_len, next_header, hop_limit, src, dst)
    # TCP 头
    tcp_header = _build_tcp_header(random.randint(1024, 65535), random.randint(1, 1023))
    tcp_data = os.urandom(max(0, payload_len - 20))
    return ipv6_header + tcp_header + tcp_data


def generate_mpls_payload(length: int, label_count: int = 1) -> bytes:
    """生成 MPLS 数据包"""
    mpls_stack = b''
    for i in range(label_count):
        label = random.randint(16, (1 << 20) - 1)
        tc = 0
        bos = 1 if i == label_count - 1 else 0
        ttl = 64
        entry = ((label & 0xFFFFF) << 12) | ((tc & 0x07) << 9) | ((bos & 0x01) << 8) | (ttl & 0xFF)
        mpls_stack += struct.pack('!I', entry)

    remaining = max(0, length - len(mpls_stack))
    if remaining >= 40:
        inner = generate_ipv4_payload(remaining)
    else:
        inner = os.urandom(remaining)
    return mpls_stack + inner


def generate_clns_payload(length: int) -> bytes:
    """生成 CLNS (ISO) 数据包"""
    # 简化的 CLNS 头部
    if length < 10:
        length = 10
    nlpid = 0x81  # ISO CLNS
    header_len = 10
    version = 1
    lifetime = 64
    flags = 0
    header = bytes([nlpid, header_len, version, lifetime, flags, 0, 0, 0, 0, 0])
    return header + os.urandom(max(0, length - len(header)))


def generate_cdp_payload(length: int) -> bytes:
    """生成 Cisco Discovery Protocol 数据包"""
    if length < 8:
        length = 8
    # CDP 头部
    version = 2
    ttl = 180
    checksum = 0
    header = struct.pack('!BBH', version, ttl, checksum)
    # 添加设备 ID TLV
    device_id = b'Router'
    tlv_type = 0x0001  # Device ID
    tlv_len = 4 + len(device_id)
    tlv = struct.pack('!HH', tlv_type, tlv_len) + device_id
    return header + tlv + os.urandom(max(0, length - len(header) - len(tlv)))


def generate_slarp_payload() -> bytes:
    """生成 SLARP (Serial Line ARP) 数据包"""
    # SLARP Request
    code = 0  # Request
    address = bytes([10, 0, 0, 1])
    mask = bytes([255, 255, 255, 0])
    unused = bytes([0] * 6)
    return struct.pack('!I', code) + address + mask + unused


def generate_client_payload(protocol: str, length: int) -> bytes:
    """根据协议类型生成客户数据"""
    if protocol == 'ipv4':
        return generate_ipv4_payload(length)
    elif protocol == 'ipv6':
        return generate_ipv6_payload(length)
    elif protocol in ('mpls', 'mpls-multicast'):
        return generate_mpls_payload(length)
    elif protocol == 'clns':
        return generate_clns_payload(length)
    elif protocol == 'cdp':
        return generate_cdp_payload(length)
    elif protocol == 'slarp':
        return generate_slarp_payload()
    else:
        return os.urandom(length)


# =============================================================================
# HDLC 控制字段构建
# =============================================================================

def build_i_frame_control(ns: int, nr: int, pf: int = 0, extended: bool = False) -> bytes:
    """构建 I 帧控制字段

    Args:
        ns: 发送序号 (N(S))
        nr: 接收序号 (N(R))
        pf: P/F 位
        extended: 是否使用扩展模式 (2 字节控制字段)

    Returns:
        控制字段字节
    """
    if extended:
        # 扩展模式: 2 字节
        # 第一字节: N(S) (7 bits) + 0
        # 第二字节: N(R) (7 bits) + P/F
        ctrl = ((ns & 0x7F) << 1) | (((nr & 0x7F) << 1) | (pf & 0x01)) << 8
        return struct.pack('!H', ctrl)
    else:
        # 基本模式: 1 字节
        # N(S) (3 bits) + P/F + N(R) (3 bits) + 0
        ctrl = ((nr & 0x07) << 5) | ((pf & 0x01) << 4) | ((ns & 0x07) << 1) | 0
        return bytes([ctrl])


def build_s_frame_control(frame_type: int, nr: int, pf: int = 0, extended: bool = False) -> bytes:
    """构建 S 帧控制字段

    Args:
        frame_type: S 帧类型 (0=RR, 1=RNR, 2=REJ, 3=SREJ)
        nr: 接收序号 (N(R))
        pf: P/F 位
        extended: 是否使用扩展模式

    Returns:
        控制字段字节
    """
    if extended:
        # 扩展模式: 2 字节
        ctrl = ((frame_type & 0x03) << 2) | 0x01 | (((nr & 0x7F) << 1) | (pf & 0x01)) << 8
        return struct.pack('!H', ctrl)
    else:
        # 基本模式: 1 字节
        ctrl = ((nr & 0x07) << 5) | ((pf & 0x01) << 4) | ((frame_type & 0x03) << 2) | 0x01
        return bytes([ctrl])


def build_u_frame_control(frame_type: int, pf: int = 0) -> bytes:
    """构建 U 帧控制字段

    Args:
        frame_type: U 帧类型 (如 UI=0x00, SABM=0x07 等)
        pf: P/F 位

    Returns:
        控制字段字节 (1 字节)
    """
    # U 帧格式: M M M P/F M M 1 1
    # frame_type 编码了 M 位
    ctrl = (frame_type & 0xEC) | ((pf & 0x01) << 4) | 0x03
    return bytes([ctrl])


# =============================================================================
# HDLC 帧构建
# =============================================================================

def build_standard_hdlc_frame(address: int,
                             control: bytes,
                             info: bytes = b'',
                             use_fcs32: bool = False,
                             include_flags: bool = True) -> bytes:
    """构建标准 HDLC 帧

    Args:
        address: 地址字段 (1 字节)
        control: 控制字段
        info: 信息字段
        use_fcs32: 是否使用 32 位 FCS
        include_flags: 是否包含首尾标志字节

    Returns:
        HDLC 帧字节串
    """
    # 组装帧 (不含标志)
    frame = bytes([address]) + control + info

    # 计算 FCS
    if use_fcs32:
        fcs = crc32_fcs(frame)
        fcs_bytes = struct.pack('<I', fcs)
    else:
        fcs = crc16_fcs(frame)
        fcs_bytes = struct.pack('<H', fcs)

    if include_flags:
        return bytes([HDLC_FLAG]) + frame + fcs_bytes + bytes([HDLC_FLAG])
    else:
        return frame + fcs_bytes


def build_cisco_hdlc_frame(address: int,
                           protocol: int,
                           info: bytes,
                           use_fcs32: bool = False,
                           include_flags: bool = True) -> bytes:
    """构建 Cisco HDLC 帧

    Args:
        address: 地址字段 (0x0F 单播, 0x8F 广播)
        protocol: 协议类型
        info: 信息字段
        use_fcs32: 是否使用 32 位 FCS
        include_flags: 是否包含首尾标志字节

    Returns:
        Cisco HDLC 帧字节串
    """
    # Cisco HDLC: Address (1B) + Control (1B, 固定 0x00) + Protocol (2B) + Info
    control = 0x00
    frame = bytes([address, control]) + struct.pack('!H', protocol) + info

    # 计算 FCS
    if use_fcs32:
        fcs = crc32_fcs(frame)
        fcs_bytes = struct.pack('<I', fcs)
    else:
        fcs = crc16_fcs(frame)
        fcs_bytes = struct.pack('<H', fcs)

    if include_flags:
        return bytes([HDLC_FLAG]) + frame + fcs_bytes + bytes([HDLC_FLAG])
    else:
        return frame + fcs_bytes


def build_hdlc_ui_frame(address: int = HDLC_ADDR_ALL_STATIONS,
                        info: bytes = b'',
                        use_fcs32: bool = False,
                        include_flags: bool = True) -> bytes:
    """构建 HDLC UI (Unnumbered Information) 帧"""
    control = build_u_frame_control(0x00, pf=0)  # UI
    return build_standard_hdlc_frame(address, control, info, use_fcs32, include_flags)


def build_hdlc_data_frame(protocol_name: str,
                          payload_len: int = 100,
                          cisco_mode: bool = False,
                          broadcast: bool = False,
                          use_fcs32: bool = False,
                          include_flags: bool = True) -> bytes:
    """构建 HDLC 数据帧

    Args:
        protocol_name: 协议名称
        payload_len: 净荷长度
        cisco_mode: 是否使用 Cisco HDLC 格式
        broadcast: 是否为广播帧 (仅 Cisco 模式)
        use_fcs32: 是否使用 32 位 FCS
        include_flags: 是否包含标志字节

    Returns:
        HDLC 帧字节串
    """
    info = generate_client_payload(protocol_name, payload_len)

    if cisco_mode:
        address = CISCO_HDLC_ADDR_BROADCAST if broadcast else CISCO_HDLC_ADDR_UNICAST
        protocol = CISCO_PROTOCOL_MAP.get(protocol_name.lower(), CISCO_PROTO_IPV4)
        return build_cisco_hdlc_frame(address, protocol, info, use_fcs32, include_flags)
    else:
        return build_hdlc_ui_frame(HDLC_ADDR_ALL_STATIONS, info, use_fcs32, include_flags)


# =============================================================================
# 帧解析
# =============================================================================

def parse_hdlc_frame(frame: bytes, cisco_mode: bool = False) -> dict:
    """解析 HDLC 帧

    Args:
        frame: HDLC 帧字节串
        cisco_mode: 是否为 Cisco HDLC 格式

    Returns:
        解析结果字典
    """
    result = {
        'valid': False,
        'address': 0,
        'control': 0,
        'protocol': 0,
        'protocol_name': '',
        'info': b'',
        'fcs_valid': None,
        'frame_type': '',
    }

    # 检查标志字节
    has_flags = len(frame) >= 2 and frame[0] == HDLC_FLAG and frame[-1] == HDLC_FLAG

    if has_flags:
        inner = frame[1:-1]
    else:
        inner = frame

    if len(inner) < 4:  # 最小: Address + Control + FCS
        return result

    # 假设 16 位 FCS
    fcs_received = struct.unpack('<H', inner[-2:])[0]
    data = inner[:-2]
    fcs_calculated = crc16_fcs(data)
    result['fcs_valid'] = (fcs_received == fcs_calculated)

    result['address'] = data[0]

    if cisco_mode:
        if len(data) < 4:
            return result
        result['control'] = data[1]
        result['protocol'] = struct.unpack('!H', data[2:4])[0]
        result['info'] = data[4:]

        # 获取协议名称
        for name, proto in CISCO_PROTOCOL_MAP.items():
            if proto == result['protocol']:
                result['protocol_name'] = name
                break
        else:
            result['protocol_name'] = f'0x{result["protocol"]:04X}'

        result['frame_type'] = 'Cisco HDLC'
    else:
        result['control'] = data[1]
        result['info'] = data[2:]

        # 判断帧类型
        ctrl = result['control']
        if (ctrl & 0x01) == 0:
            result['frame_type'] = 'I'
        elif (ctrl & 0x03) == 0x01:
            result['frame_type'] = 'S'
        else:
            result['frame_type'] = 'U'

    result['valid'] = True
    return result


# =============================================================================
# 帧生成与 I/O
# =============================================================================

def generate_hdlc_frames(count: int = 1,
                         protocol: str = 'ipv4',
                         payload_len: int = 100,
                         cisco_mode: bool = False,
                         broadcast: bool = False,
                         use_fcs32: bool = False,
                         include_flags: bool = True) -> List[bytes]:
    """批量生成 HDLC 帧

    Args:
        count: 生成帧数
        protocol: 协议类型
        payload_len: 净荷长度
        cisco_mode: 是否使用 Cisco HDLC 格式
        broadcast: 是否为广播帧
        use_fcs32: 是否使用 32 位 FCS
        include_flags: 是否包含标志字节

    Returns:
        HDLC 帧列表
    """
    frames = []
    for _ in range(count):
        frame = build_hdlc_data_frame(
            protocol_name=protocol,
            payload_len=payload_len,
            cisco_mode=cisco_mode,
            broadcast=broadcast,
            use_fcs32=use_fcs32,
            include_flags=include_flags
        )
        frames.append(frame)
    return frames


def write_hdlc_pcap(frames: List[bytes], filename: str, cisco_mode: bool = False) -> None:
    """将 HDLC 帧写入 pcap 文件

    Args:
        frames: HDLC 帧列表
        filename: 输出文件名
        cisco_mode: 是否为 Cisco HDLC 格式
    """
    # linktype: 104 = Cisco HDLC, 16 = HDLC
    # 注意: Wireshark 对 HDLC 的支持可能需要特定配置
    if cisco_mode:
        linktype = 104  # DLT_C_HDLC (Cisco HDLC)
    else:
        linktype = 50   # DLT_HDLC (Generic HDLC)

    with open(filename, 'wb') as f:
        # 写入 pcap 全局头
        global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
        f.write(global_header)

        for frame in frames:
            now = time.time()
            ts_sec = int(now)
            ts_usec = int((now - ts_sec) * 1_000_000)
            if frame and len(frame) >= 6:
                if frame[0] == HDLC_FLAG and frame[-1] == HDLC_FLAG:
                    # 去掉首尾 Flag (各1字节) 和 FCS (2字节，假设16位FCS)
                    frame = frame[1:-3]
            incl_len = len(frame)
            orig_len = incl_len
            packet_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(packet_header)
            f.write(frame)


def write_hdlc_binary(frames: List[bytes], filename: str) -> None:
    """将 HDLC 帧写入二进制文件"""
    with open(filename, 'wb') as f:
        for frame in frames:
            f.write(struct.pack('!H', len(frame)))
            f.write(frame)


# =============================================================================
# 辅助函数
# =============================================================================

def get_protocol_name(protocol: int) -> str:
    """获取协议号对应的名称"""
    for name, proto in CISCO_PROTOCOL_MAP.items():
        if proto == protocol:
            return name.upper()
    return f'0x{protocol:04X}'


def print_frame_info(frame: bytes, index: int = 0, cisco_mode: bool = False) -> None:
    """打印 HDLC 帧信息"""
    result = parse_hdlc_frame(frame, cisco_mode)

    print(f"=== HDLC Frame #{index} ===")
    print(f"  Total Length: {len(frame)} bytes")
    print(f"  Valid: {result['valid']}")
    print(f"  Frame Type: {result['frame_type']}")
    print(f"  Address: 0x{result['address']:02X}")
    print(f"  Control: 0x{result['control']:02X}")
    if cisco_mode:
        print(f"  Protocol: 0x{result['protocol']:04X} ({result['protocol_name']})")
    print(f"  Info Length: {len(result['info'])} bytes")
    if result['fcs_valid'] is not None:
        print(f"  FCS Valid: {result['fcs_valid']}")


# =============================================================================
# 命令行接口
# =============================================================================

def _parse_args():
    p = argparse.ArgumentParser(
        description='HDLC (High-Level Data Link Control) 帧生成器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s --count 10 --protocol ipv4 --out hdlc_frames.pcap
  %(prog)s --count 5 --cisco --protocol ipv6 --out cisco_hdlc.pcap
  %(prog)s --count 10 --cisco --protocol mpls --fcs32 --out hdlc_mpls.pcap
  %(prog)s --in hdlc_frames.bin --info
        '''
    )

    p.add_argument('--count', '-c', type=int, default=1000,
                   help='生成帧数 (默认: 1000)')
    p.add_argument('--protocol', '-p', type=str, default='ipv4',
                   choices=['ipv4', 'ipv6', 'mpls', 'mpls-multicast', 'clns', 'cdp', 'slarp', 'ipx', 'raw'],
                   help='上层协议类型 (默认: ipv4)')
    p.add_argument('--payload-len', '-l', type=int, default=100,
                   help='净荷长度 (默认: 100)')
    p.add_argument('--cisco', action='store_true', default=False,
                   help='使用 Cisco HDLC 格式')
    p.add_argument('--broadcast', action='store_true', default=False,
                   help='生成广播帧 (仅 Cisco 模式)')
    p.add_argument('--fcs32', action='store_true', default=False,
                   help='使用 32 位 FCS (默认 16 位)')
    p.add_argument('--no-flags', action='store_true', default=False,
                   help='不包含首尾标志字节')
    p.add_argument('--out', '-o', type=str, default='hdlc_frames.pcap',
                   help='输出文件 (默认: hdlc_frames.pcap)')
    p.add_argument('--format', '-f', type=str, default='pcap',
                   choices=['bin', 'pcap'],
                   help='输出格式 (默认: pcap)')
    p.add_argument('--info', action='store_true',
                   help='显示帧详细信息')

    return p.parse_args()


if __name__ == '__main__':
    args = _parse_args()

    # 生成 HDLC 帧
    frames = generate_hdlc_frames(
        count=args.count,
        protocol=args.protocol,
        payload_len=args.payload_len,
        cisco_mode=args.cisco,
        broadcast=args.broadcast,
        use_fcs32=args.fcs32,
        include_flags=not args.no_flags
    )

    if args.format == 'pcap':
        write_hdlc_pcap(frames, args.out, args.cisco)
    else:
        write_hdlc_binary(frames, args.out)

    mode_str = "Cisco HDLC" if args.cisco else "标准 HDLC"
    print(f'已生成 {len(frames)} 个 {mode_str} 帧并写入 {args.out}')
