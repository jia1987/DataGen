"""PPP (Point-to-Point Protocol) 帧生成器

基于 RFC 1661 (PPP), RFC 1662 (PPP in HDLC-like Framing) 标准实现

功能:
- 支持多种上层协议封装: IPv4, IPv6, MPLS, OSI, IPX 等
- 支持 HDLC-like 帧封装 (带 Flag, Address, Control, FCS)
- 支持地址/控制字段压缩 (ACFC)
- 支持协议字段压缩 (PFC)
- 支持 LCP, IPCP, IPV6CP 等控制协议帧
- 导出为 pcap 文件

PPP 帧结构 (RFC 1662 HDLC-like Framing):
+----------+----------+----------+----------+-------------+----------+----------+
|   Flag   | Address  | Control  | Protocol |    Info     |   FCS    |   Flag   |
|  (0x7E)  |  (0xFF)  |  (0x03)  | (1-2B)   | (Variable)  | (2-4B)   |  (0x7E)  |
+----------+----------+----------+----------+-------------+----------+----------+

用法示例:
  python PPP_gen.py --count 10 --protocol ipv4 --out ppp_frames.pcap
  python PPP_gen.py --count 5 --protocol ipv6 --hdlc --out ppp_hdlc.pcap

"""

from __future__ import annotations

import argparse
import os
import random
import struct
import time
from typing import List, Optional

# =============================================================================
# PPP 常量定义
# =============================================================================

# PPP 标志字节
PPP_FLAG = 0x7E
PPP_ADDRESS = 0xFF  # 全站地址
PPP_CONTROL = 0x03  # 无编号信息

# PPP 协议字段 (RFC 1700, RFC 3232)
PPP_PROTO_IPV4 = 0x0021          # Internet Protocol version 4
PPP_PROTO_IPV6 = 0x0057          # Internet Protocol version 6
PPP_PROTO_MPLS_UNICAST = 0x0281  # MPLS Unicast
PPP_PROTO_MPLS_MULTICAST = 0x0283  # MPLS Multicast
PPP_PROTO_OSI = 0x0023           # OSI Network Layer
PPP_PROTO_IPX = 0x002B           # Novell IPX
PPP_PROTO_APPLETALK = 0x0029     # AppleTalk
PPP_PROTO_VJ_COMP = 0x002D       # Van Jacobson Compressed TCP/IP
PPP_PROTO_VJ_UNCOMP = 0x002F     # Van Jacobson Uncompressed TCP/IP
PPP_PROTO_BRIDGING = 0x0031      # Bridging PDU
PPP_PROTO_CDP = 0x0207           # Cisco Discovery Protocol

# PPP 控制协议
PPP_PROTO_LCP = 0xC021           # Link Control Protocol
PPP_PROTO_PAP = 0xC023           # Password Authentication Protocol
PPP_PROTO_CHAP = 0xC223          # Challenge Handshake Auth Protocol
PPP_PROTO_IPCP = 0x8021          # IP Control Protocol
PPP_PROTO_IPV6CP = 0x8057        # IPv6 Control Protocol
PPP_PROTO_CCP = 0x80FD           # Compression Control Protocol
PPP_PROTO_ECP = 0x8053           # Encryption Control Protocol
PPP_PROTO_MPLSCP = 0x8281        # MPLS Control Protocol

# LCP 代码
LCP_CODE_CONFIGURE_REQUEST = 1
LCP_CODE_CONFIGURE_ACK = 2
LCP_CODE_CONFIGURE_NAK = 3
LCP_CODE_CONFIGURE_REJECT = 4
LCP_CODE_TERMINATE_REQUEST = 5
LCP_CODE_TERMINATE_ACK = 6
LCP_CODE_CODE_REJECT = 7
LCP_CODE_PROTOCOL_REJECT = 8
LCP_CODE_ECHO_REQUEST = 9
LCP_CODE_ECHO_REPLY = 10
LCP_CODE_DISCARD_REQUEST = 11

# LCP 选项类型
LCP_OPT_MRU = 1                  # Maximum Receive Unit
LCP_OPT_ACCM = 2                 # Async Control Character Map
LCP_OPT_AUTH = 3                 # Authentication Protocol
LCP_OPT_QUALITY = 4              # Quality Protocol
LCP_OPT_MAGIC = 5                # Magic Number
LCP_OPT_PFC = 7                  # Protocol Field Compression
LCP_OPT_ACFC = 8                 # Address-and-Control-Field-Compression

# 协议名称到协议号的映射
PROTOCOL_MAP = {
    'ipv4': PPP_PROTO_IPV4,
    'ipv6': PPP_PROTO_IPV6,
    'mpls': PPP_PROTO_MPLS_UNICAST,
    'mpls-multicast': PPP_PROTO_MPLS_MULTICAST,
    'osi': PPP_PROTO_OSI,
    'ipx': PPP_PROTO_IPX,
    'appletalk': PPP_PROTO_APPLETALK,
    'bridging': PPP_PROTO_BRIDGING,
    'lcp': PPP_PROTO_LCP,
    'ipcp': PPP_PROTO_IPCP,
    'ipv6cp': PPP_PROTO_IPV6CP,
    'pap': PPP_PROTO_PAP,
    'chap': PPP_PROTO_CHAP,
}

# =============================================================================
# CRC 计算函数
# =============================================================================


def _make_crc16_table() -> List[int]:
    """生成 CRC-16-CCITT 查找表 (用于 PPP FCS)

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
    """计算 PPP FCS-16 (RFC 1662)

    初始值: 0xFFFF
    最终异或: 0xFFFF
    """
    crc = 0xFFFF
    for byte in data:
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFF


def _make_crc32_table() -> List[int]:
    """生成 CRC-32 查找表 (用于 PPP FCS-32)

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
    """计算 PPP FCS-32"""
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


def generate_client_payload(protocol: str, length: int) -> bytes:
    """根据协议类型生成客户数据"""
    if protocol in ('ipv4', 'ipcp'):
        return generate_ipv4_payload(length)
    elif protocol in ('ipv6', 'ipv6cp'):
        return generate_ipv6_payload(length)
    elif protocol in ('mpls', 'mpls-multicast'):
        return generate_mpls_payload(length)
    else:
        return os.urandom(length)


# =============================================================================
# LCP/NCP 帧生成
# =============================================================================

def build_lcp_option(opt_type: int, data: bytes) -> bytes:
    """构建 LCP 选项"""
    length = 2 + len(data)
    return bytes([opt_type, length]) + data


def build_lcp_frame(code: int, identifier: int, options: Optional[List[bytes]] = None) -> bytes:
    """构建 LCP 帧

    LCP 帧格式:
    +----------+----------+----------+----------+-------------+
    |   Code   |   ID     |       Length        |    Data     |
    |  (1B)    |  (1B)    |       (2B)          |  (Variable) |
    +----------+----------+----------+----------+-------------+
    """
    options = options or []
    data = b''.join(options)
    length = 4 + len(data)  # Code + ID + Length + Data
    return struct.pack('!BBH', code, identifier, length) + data


def build_configure_request(identifier: int = 1) -> bytes:
    """构建 LCP Configure-Request 帧"""
    options = [
        build_lcp_option(LCP_OPT_MRU, struct.pack('!H', 1500)),  # MRU = 1500
        build_lcp_option(LCP_OPT_MAGIC, struct.pack('!I', random.randint(0, 0xFFFFFFFF))),  # Magic Number
        build_lcp_option(LCP_OPT_ACFC, b''),  # ACFC
        build_lcp_option(LCP_OPT_PFC, b''),   # PFC
    ]
    return build_lcp_frame(LCP_CODE_CONFIGURE_REQUEST, identifier, options)


def build_configure_ack(identifier: int, options: List[bytes]) -> bytes:
    """构建 LCP Configure-Ack 帧"""
    return build_lcp_frame(LCP_CODE_CONFIGURE_ACK, identifier, options)


def build_echo_request(identifier: int = 1, magic: Optional[int] = None) -> bytes:
    """构建 LCP Echo-Request 帧"""
    if magic is None:
        magic = random.randint(0, 0xFFFFFFFF)
    data = struct.pack('!I', magic)
    return build_lcp_frame(LCP_CODE_ECHO_REQUEST, identifier, [data])


def build_echo_reply(identifier: int, magic: int) -> bytes:
    """构建 LCP Echo-Reply 帧"""
    data = struct.pack('!I', magic)
    return build_lcp_frame(LCP_CODE_ECHO_REPLY, identifier, [data])


# =============================================================================
# PPP 帧构建
# =============================================================================

def build_ppp_frame(protocol: int,
                    payload: bytes,
                    hdlc_framing: bool = False,
                    use_fcs32: bool = False,
                    compress_protocol: bool = False,
                    compress_ac: bool = False) -> bytes:
    """构建 PPP 帧

    Args:
        protocol: PPP 协议号
        payload: 信息字段内容
        hdlc_framing: 是否使用 HDLC-like 封装 (带 Flag, Address, Control, FCS)
        use_fcs32: 是否使用 32 位 FCS (默认 16 位)
        compress_protocol: 是否压缩协议字段 (PFC)
        compress_ac: 是否压缩地址/控制字段 (ACFC)

    Returns:
        PPP 帧字节串
    """
    # 协议字段
    if compress_protocol and protocol <= 0xFF:
        proto_field = bytes([protocol])
    else:
        proto_field = struct.pack('!H', protocol)

    if hdlc_framing:
        # HDLC-like 封装
        frame = b''

        # 地址/控制字段
        if not compress_ac:
            frame += bytes([PPP_ADDRESS, PPP_CONTROL])

        # 协议字段 + 信息
        frame += proto_field + payload

        # 计算 FCS
        if use_fcs32:
            fcs = crc32_fcs(frame)
            fcs_bytes = struct.pack('<I', fcs)
        else:
            fcs = crc16_fcs(frame)
            fcs_bytes = struct.pack('<H', fcs)

        # 组装完整帧
        return bytes([PPP_FLAG]) + frame + fcs_bytes + bytes([PPP_FLAG])
    else:
        # 无 HDLC 封装 (如 PPPoE 中的 PPP)
        if not compress_ac:
            return bytes([PPP_ADDRESS, PPP_CONTROL]) + proto_field + payload
        else:
            return proto_field + payload


def build_ppp_data_frame(protocol_name: str,
                         payload_len: int = 100,
                         hdlc_framing: bool = False,
                         use_fcs32: bool = False,
                         compress_protocol: bool = False,
                         compress_ac: bool = False) -> bytes:
    """构建 PPP 数据帧

    Args:
        protocol_name: 协议名称 (ipv4, ipv6, mpls 等)
        payload_len: 净荷长度
        hdlc_framing: 是否使用 HDLC-like 封装
        use_fcs32: 是否使用 32 位 FCS
        compress_protocol: 是否压缩协议字段
        compress_ac: 是否压缩地址/控制字段

    Returns:
        PPP 帧字节串
    """
    protocol = PROTOCOL_MAP.get(protocol_name.lower(), PPP_PROTO_IPV4)
    payload = generate_client_payload(protocol_name, payload_len)

    return build_ppp_frame(
        protocol=protocol,
        payload=payload,
        hdlc_framing=hdlc_framing,
        use_fcs32=use_fcs32,
        compress_protocol=compress_protocol,
        compress_ac=compress_ac
    )


def build_ppp_lcp_frame(lcp_payload: bytes,
                        hdlc_framing: bool = False,
                        use_fcs32: bool = False) -> bytes:
    """构建 PPP LCP 帧"""
    return build_ppp_frame(
        protocol=PPP_PROTO_LCP,
        payload=lcp_payload,
        hdlc_framing=hdlc_framing,
        use_fcs32=use_fcs32,
        compress_protocol=False,  # LCP 不压缩协议字段
        compress_ac=False         # LCP 不压缩地址/控制字段
    )


# =============================================================================
# 帧解析
# =============================================================================

def parse_ppp_frame(frame: bytes, hdlc_framing: bool = False) -> dict:
    """解析 PPP 帧

    Args:
        frame: PPP 帧字节串
        hdlc_framing: 是否为 HDLC-like 封装

    Returns:
        解析结果字典
    """
    result = {
        'valid': False,
        'protocol': 0,
        'protocol_name': '',
        'payload': b'',
        'fcs_valid': None,
        'has_ac': False,
        'compressed_proto': False,
    }

    if hdlc_framing:
        # 检查 Flag
        if len(frame) < 7 or frame[0] != PPP_FLAG or frame[-1] != PPP_FLAG:
            return result

        # 去除首尾 Flag
        inner = frame[1:-1]

        # 提取 FCS (假设 16 位)
        fcs_received = struct.unpack('<H', inner[-2:])[0]
        data = inner[:-2]

        # 验证 FCS
        fcs_calculated = crc16_fcs(data)
        result['fcs_valid'] = (fcs_received == fcs_calculated)

        pos = 0
    else:
        data = frame
        pos = 0

    # 检查地址/控制字段
    if len(data) >= pos + 2 and data[pos] == PPP_ADDRESS and data[pos + 1] == PPP_CONTROL:
        result['has_ac'] = True
        pos += 2

    # 提取协议字段
    if len(data) <= pos:
        return result

    if data[pos] & 0x01:
        # 压缩的协议字段 (1 字节)
        result['protocol'] = data[pos]
        result['compressed_proto'] = True
        pos += 1
    else:
        # 非压缩的协议字段 (2 字节)
        if len(data) < pos + 2:
            return result
        result['protocol'] = struct.unpack('!H', data[pos:pos + 2])[0]
        pos += 2

    # 提取净荷
    result['payload'] = data[pos:]

    # 获取协议名称
    for name, proto in PROTOCOL_MAP.items():
        if proto == result['protocol']:
            result['protocol_name'] = name
            break
    else:
        result['protocol_name'] = f'0x{result["protocol"]:04X}'

    result['valid'] = True
    return result


# =============================================================================
# 帧生成与 I/O
# =============================================================================

def generate_ppp_frames(count: int = 1,
                        protocol: str = 'ipv4',
                        payload_len: int = 100,
                        hdlc_framing: bool = False,
                        use_fcs32: bool = False,
                        compress_protocol: bool = False,
                        compress_ac: bool = False,
                        include_lcp_ratio: float = 0.0) -> List[bytes]:
    """批量生成 PPP 帧

    Args:
        count: 生成帧数
        protocol: 协议类型
        payload_len: 净荷长度
        hdlc_framing: 是否使用 HDLC 封装
        use_fcs32: 是否使用 32 位 FCS
        compress_protocol: 是否压缩协议字段
        compress_ac: 是否压缩地址/控制字段
        include_lcp_ratio: LCP 帧比例

    Returns:
        PPP 帧列表
    """
    frames = []
    lcp_id = 1

    for _ in range(count):
        if include_lcp_ratio > 0 and random.random() < include_lcp_ratio:
            # 生成 LCP 帧
            if random.random() < 0.5:
                lcp_payload = build_configure_request(lcp_id)
            else:
                lcp_payload = build_echo_request(lcp_id)
            lcp_id = (lcp_id % 255) + 1
            frame = build_ppp_lcp_frame(lcp_payload, hdlc_framing, use_fcs32)
        else:
            # 生成数据帧
            frame = build_ppp_data_frame(
                protocol_name=protocol,
                payload_len=payload_len,
                hdlc_framing=hdlc_framing,
                use_fcs32=use_fcs32,
                compress_protocol=compress_protocol,
                compress_ac=compress_ac
            )
        frames.append(frame)

    return frames


def write_ppp_pcap(frames: List[bytes], filename: str, hdlc_framing: bool = False) -> None:
    """将 PPP 帧写入 pcap 文件

    Args:
        frames: PPP 帧列表
        filename: 输出文件名
        hdlc_framing: 是否为 HDLC 封装 (影响 linktype)
    """
    # linktype: 9 = PPP, 50 = PPP_HDLC (DLT_PPP_SERIAL)
    # 注意: DLT_PPP_SERIAL 期望帧不包含 Flag (0x7E) 和 FCS
    if hdlc_framing:
        linktype = 50  # DLT_PPP_SERIAL (PPP over HDLC)
    else:
        linktype = 9   # DLT_PPP

    with open(filename, 'wb') as f:
        # 写入 pcap 全局头
        global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
        f.write(global_header)

        for frame in frames:
            now = time.time()
            ts_sec = int(now)
            ts_usec = int((now - ts_sec) * 1_000_000)

            # 对于 HDLC 封装的帧，需要去掉首尾 Flag 和 FCS
            # 原始帧格式: Flag + Address + Control + Protocol + Info + FCS + Flag
            # pcap 期望格式: Address + Control + Protocol + Info
            if hdlc_framing and len(frame) >= 6:
                if frame[0] == PPP_FLAG and frame[-1] == PPP_FLAG:
                    # 去掉首尾 Flag (各1字节) 和 FCS (2字节，假设16位FCS)
                    frame = frame[1:-3]

            incl_len = len(frame)
            orig_len = incl_len
            packet_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(packet_header)
            f.write(frame)


def write_ppp_binary(frames: List[bytes], filename: str) -> None:
    """将 PPP 帧写入二进制文件"""
    with open(filename, 'wb') as f:
        for frame in frames:
            f.write(struct.pack('!H', len(frame)))
            f.write(frame)


# =============================================================================
# 辅助函数
# =============================================================================

def get_protocol_name(protocol: int) -> str:
    """获取协议号对应的名称"""
    for name, proto in PROTOCOL_MAP.items():
        if proto == protocol:
            return name.upper()
    return f'0x{protocol:04X}'


def print_frame_info(frame: bytes, index: int = 0, hdlc_framing: bool = False) -> None:
    """打印 PPP 帧信息"""
    result = parse_ppp_frame(frame, hdlc_framing)

    print(f"=== PPP Frame #{index} ===")
    print(f"  Total Length: {len(frame)} bytes")
    print(f"  Valid: {result['valid']}")
    print(f"  Protocol: 0x{result['protocol']:04X} ({result['protocol_name']})")
    print(f"  Has Address/Control: {result['has_ac']}")
    print(f"  Compressed Protocol: {result['compressed_proto']}")
    print(f"  Payload Length: {len(result['payload'])} bytes")
    if result['fcs_valid'] is not None:
        print(f"  FCS Valid: {result['fcs_valid']}")


# =============================================================================
# 命令行接口
# =============================================================================

def _parse_args():
    p = argparse.ArgumentParser(
        description='PPP (Point-to-Point Protocol) 帧生成器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s --count 10 --protocol ipv4 --out ppp_frames.pcap
  %(prog)s --count 5 --protocol ipv6 --hdlc --out ppp_hdlc.pcap
  %(prog)s --count 100 --protocol mpls --hdlc --fcs32 --out ppp_mpls.pcap
  %(prog)s --in ppp_frames.bin --info
        '''
    )

    p.add_argument('--count', '-c', type=int, default=1000,
                   help='生成帧数 (默认: 1000)')
    p.add_argument('--protocol', '-p', type=str, default='ipv4',
                   choices=['ipv4', 'ipv6', 'mpls', 'mpls-multicast', 'osi', 'ipx', 'lcp', 'raw'],
                   help='上层协议类型 (默认: ipv4)')
    p.add_argument('--payload-len', '-l', type=int, default=100,
                   help='净荷长度 (默认: 100)')
    p.add_argument('--hdlc', action='store_true', default=True,
                   help='使用 HDLC-like 封装 (带 Flag, FCS)')
    p.add_argument('--fcs32', action='store_true', default=False,
                   help='使用 32 位 FCS (默认 16 位)')
    p.add_argument('--pfc', action='store_true', default=False,
                   help='启用协议字段压缩')
    p.add_argument('--acfc', action='store_true', default=False,
                   help='启用地址/控制字段压缩')
    p.add_argument('--lcp-ratio', type=float, default=0.0,
                   help='LCP 帧比例 (0.0-1.0, 默认: 0.0)')
    p.add_argument('--out', '-o', type=str, default='ppp_frames.pcap',
                   help='输出文件 (默认: ppp_frames.pcap)')
    p.add_argument('--format', '-f', type=str, default='pcap',
                   choices=['bin', 'pcap'],
                   help='输出格式 (默认: pcap)')

    return p.parse_args()


if __name__ == '__main__':
    args = _parse_args()

    # 生成 PPP 帧
    frames = generate_ppp_frames(
        count=args.count,
        protocol=args.protocol,
        payload_len=args.payload_len,
        hdlc_framing=args.hdlc,
        use_fcs32=args.fcs32,
        compress_protocol=args.pfc,
        compress_ac=args.acfc,
        include_lcp_ratio=args.lcp_ratios
    )

    if args.format == 'pcap':
        write_ppp_pcap(frames, args.out, args.hdlc)
    else:
        write_ppp_binary(frames, args.out)

    print(f'已生成 {len(frames)} 个 PPP 帧并写入 {args.out}')
