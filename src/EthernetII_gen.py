"""Ethernet II frames Generator

功能:
- 生成指定数量的 Ethernet II 帧，支持多种净荷类型（ipv4, ipv6, arp, mpls, raw）
- 支持单/双 VLAN tag（802.1Q / QinQ）
- 支持 Jumbo Frames（可指定净荷长度 > 1500）
- 从 pcap 文件导入帧
- 导出帧为 pcap 文件

实现说明:
- 使用纯 Python 实现简单 PCAP 读写（兼容常见 pcap 文件，基于 libpcap 全局头）
- 生成的净荷为填充/随机/或用户提供的 bytes；某些类型（如 MPLS）会在以太类型位置使用相应值

用法示例:
  python EthernetII_gen.py --count 10 --payload ipv4 --out frames.pcap

"""

from __future__ import annotations

import argparse
import os
import random
import struct
import time
from typing import List, Optional, Tuple, Union

# 常用以太类型
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_MPLS_UNI = 0x8847
ETHERTYPE_MPLS_MULTI = 0x8848

PCAP_MAGIC_BE = 0xa1b2c3d4
PCAP_MAGIC_LE = 0xd4c3b2a1


def mac_str_to_bytes(mac: str) -> bytes:
    parts = mac.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("MAC 必须为 6 个字节，例如 00:11:22:33:44:55")
    return bytes(int(p, 16) for p in parts)


def random_mac() -> bytes:
    return bytes((random.randint(0, 255) for _ in range(6)))


def make_eth_header(dst: bytes, src: bytes, ethertype: int) -> bytes:
    return dst + src + struct.pack('!H', ethertype)


def build_payload(payload_type: str, length: int, extra: Optional[dict] = None) -> bytes:
    """根据类型构造净荷（返回原始 bytes，不包含以太头）

    payload_type: ipv4|ipv6|arp|mpls|raw
    extra: 额外参数（可选）
    """
    extra = extra or {}
    if payload_type == 'ipv4':
        # 生成伪 IPv4 数据包（不保证为有效 IP 帧，仅用于占位）
        version_ihl = 0x45
        tos = 0
        total_length = length if length >= 20 else 20
        ident = 0
        flags_frag = 0
        ttl = 64
        proto = extra.get('proto', 0)
        checksum = 0
        src_ip = extra.get('src_ip', b'\x0a\x00\x00\x01')
        dst_ip = extra.get('dst_ip', b'\x0a\x00\x00\x02')
        header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, ident, flags_frag, ttl, proto, checksum, src_ip, dst_ip)
        body = os.urandom(max(0, length - len(header)))
        return header + body
    elif payload_type == 'ipv6':
        payload_len = max(0, length - 40)
        ver_tc_flow = (6 << 28)
        payload_proto = extra.get('proto', 0)
        hop_limit = 64
        src = extra.get('src_ip', os.urandom(16))
        dst = extra.get('dst_ip', os.urandom(16))
        header = struct.pack('!IHBB16s16s', ver_tc_flow, payload_len, payload_proto, hop_limit, src, dst)
        return header + os.urandom(payload_len)
    elif payload_type == 'arp':
        # Ethernet + IPv4 ARP packet (28 bytes) + padding
        htype = 1
        ptype = ETHERTYPE_IPV4
        hlen = 6
        plen = 4
        oper = 1
        sha = extra.get('sha', os.urandom(6))
        spa = extra.get('spa', b'\x0a\x00\x00\x01')
        tha = extra.get('tha', b'\x00' * 6)
        tpa = extra.get('tpa', b'\x0a\x00\x00\x02')
        arp = struct.pack('!HHBBH6s4s6s4s', htype, ptype, hlen, plen, oper, sha, spa, tha, tpa)
        return arp + os.urandom(max(0, length - len(arp)))
    elif payload_type == 'mpls':
        # MPLS 标签 (4 bytes each). 我们生成一个或多个标签然后随附原始负载
        labels = extra.get('labels', [random.randint(0, (1 << 20) - 1)])
        mpls_bytes = b''
        for i, lbl in enumerate(labels):
            bos = 1 if i == len(labels) - 1 else 0
            s_ttl = 255
            entry = ((lbl & 0xFFFFF) << 12) | (0 << 9) | (bos << 8) | s_ttl
            mpls_bytes += struct.pack('!I', entry)
        return mpls_bytes + os.urandom(max(0, length - len(mpls_bytes)))
    elif payload_type == 'raw':
        return extra.get('data', os.urandom(length))
    else:
        # 默认随机净荷
        return os.urandom(length)


def build_ethernet_frame(dst_mac: Union[str, bytes], src_mac: Union[str, bytes], payload_type: str = 'raw',
                         payload_len: int = 46, vlan: Optional[int] = None, qinq: Optional[int] = None,
                         mpls_labels: Optional[List[int]] = None, raw_payload: Optional[bytes] = None) -> bytes:
    """构造完整的 Ethernet II 帧（bytes）

    - 如果 vlan 不为 None，则在以太类型前插入 802.1Q tag（ethertype 0x8100）
    - 如果 qinq 不为 None，则插入双标签（QinQ）
    - payload_len 指净荷长度（不含以太头），如果提供 raw_payload 则以该数据为准
    """
    if isinstance(dst_mac, str):
        dst = mac_str_to_bytes(dst_mac)
    else:
        dst = bytes(dst_mac) if not isinstance(dst_mac, bytes) else dst_mac
    if isinstance(src_mac, str):
        src = mac_str_to_bytes(src_mac)
    else:
        src = bytes(src_mac) if not isinstance(src_mac, bytes) else src_mac

    extra = {}
    if mpls_labels:
        extra['labels'] = mpls_labels
    if raw_payload is not None:
        payload = raw_payload
    else:
        payload = build_payload(payload_type, payload_len, extra)

    # 根据 payload_type 确定以太类型
    if payload_type == 'ipv4':
        eth_type_after = ETHERTYPE_IPV4
    elif payload_type == 'ipv6':
        eth_type_after = ETHERTYPE_IPV6
    elif payload_type == 'arp':
        eth_type_after = ETHERTYPE_ARP
    elif payload_type == 'mpls':
        eth_type_after = ETHERTYPE_MPLS_UNI
    else:
        eth_type_after = ETHERTYPE_IPV4

    # 处理 VLAN / QinQ
    if qinq is not None:
        # outer tag: 0x88A8 (provider), inner tag: 0x8100 (customer)
        outer_tag = struct.pack('!H', ETHERTYPE_QINQ) + struct.pack('!H', qinq)
        if vlan is None:
            # 如果没有客户 VLAN，使用 0
            inner_tci = 0
        else:
            inner_tci = vlan
        inner_tag = struct.pack('!H', ETHERTYPE_VLAN) + struct.pack('!H', inner_tci)
        ethertype_field = struct.pack('!H', eth_type_after)
        header = dst + src + outer_tag + inner_tag + ethertype_field
        return header + payload
    elif vlan is not None:
        # 单 VLAN tag
        vlan_tag = struct.pack('!H', ETHERTYPE_VLAN) + struct.pack('!H', vlan)
        ethertype_field = struct.pack('!H', eth_type_after)
        header = dst + src + vlan_tag + ethertype_field
        return header + payload
    else:
        # 无 VLAN
        header = dst + src + struct.pack('!H', eth_type_after)
        return header + payload


def write_pcap(frames: Union[List[bytes], List[Tuple[int, int, bytes]]], filename: str) -> None:
    """将帧列表写入 pcap 文件。

    frames: 可以是 bytes 列表，或 (ts_sec, ts_usec, data) 元组列表
    """
    with open(filename, 'wb') as f:
        # 写入 pcap 全局头 (24 bytes)
        # magic, version_major, version_minor, thiszone, sigfigs, snaplen, network
        # 使用原生字节序 magic 0xa1b2c3d4，小端写入后文件中为 d4 c3 b2 a1
        global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        f.write(global_header)

        for frame in frames:
            if isinstance(frame, tuple) and len(frame) == 3:
                ts_sec, ts_usec, data = frame
            else:
                # 使用当前时间
                now = time.time()
                ts_sec = int(now)
                ts_usec = int((now - ts_sec) * 1_000_000)
                data = frame
            incl_len = len(data)
            orig_len = incl_len
            # 写入包头 (16 bytes)
            packet_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(packet_header)
            f.write(data)


def read_pcap(filename: str) -> List[Tuple[int, int, bytes]]:
    """从 pcap 文件读取帧，返回 (ts_sec, ts_usec, data) 列表。

    仅支持常见 libpcap 小端/大端格式。
    """
    res = []
    with open(filename, 'rb') as f:
        raw_gh = f.read(24)
        if len(raw_gh) < 24:
            raise ValueError('不是有效的 pcap 文件')
        magic = struct.unpack('<I', raw_gh[:4])[0]
        if magic == PCAP_MAGIC_LE:
            endian = '<'
        elif magic == PCAP_MAGIC_BE:
            endian = '>'
        else:
            # 也尝试大端读取
            magic_be = struct.unpack('>I', raw_gh[:4])[0]
            if magic_be == PCAP_MAGIC_LE:
                endian = '<'
            elif magic_be == PCAP_MAGIC_BE:
                endian = '>'
            else:
                raise ValueError('未知 pcap magic')
        # 我们不需要解析 global header 其他字段
        # 从文件当前位置读取记录
        while True:
            ph = f.read(16)
            if not ph:
                break
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', ph)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            res.append((ts_sec, ts_usec, data))
    return res


def generate_frames(count: int = 1, payload: str = 'ipv4', payload_len: int = 100,
                    src_mac: Optional[str] = None, dst_mac: Optional[str] = None,
                    vlan: Optional[int] = None, qinq: Optional[int] = None,
                    mpls_labels: Optional[List[int]] = None,
                    raw_payload: Optional[bytes] = None) -> List[bytes]:
    frames = []
    src = src_mac or ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6))
    dst = dst_mac or ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6))
    for _ in range(count):
        f = build_ethernet_frame(dst, src, payload_type=payload, payload_len=payload_len,
                                 vlan=vlan, qinq=qinq, mpls_labels=mpls_labels, raw_payload=raw_payload)
        frames.append(f)
    return frames


def _parse_args():
    p = argparse.ArgumentParser(description='Ethernet II 帧生成与 pcap I/O')
    p.add_argument('--count', '-c', type=int, default=10000, help='生成帧数')
    p.add_argument('--payload', choices=['ipv4', 'ipv6', 'arp', 'mpls', 'raw'], default='ipv4')
    p.add_argument('--payload-len', type=int, default=100, help='净荷长度（字节）')
    p.add_argument('--src', type=str, default=None, help='源 MAC 地址，例如 00:11:22:33:44:55')
    p.add_argument('--dst', type=str, default=None, help='目标 MAC 地址')
    p.add_argument('--vlan', type=int, default=None, help='802.1Q VLAN ID (0-4095)')
    p.add_argument('--qinq', type=int, default=None, help='外层 QinQ VLAN ID')
    p.add_argument('--out', type=str, default='out.pcap', help='输出 pcap 文件')
    p.add_argument('--in', dest='infile', type=str, default=None, help='从 pcap 文件导入帧并显示计数')
    return p.parse_args()


if __name__ == '__main__':
    args = _parse_args()
    if args.infile:
        frames = read_pcap(args.infile)
        print(f'从 {args.infile} 读取到 {len(frames)} 帧')
    else:
        frames = generate_frames(count=args.count, payload=args.payload, payload_len=args.payload_len,
                                 src_mac=args.src, dst_mac=args.dst, vlan=args.vlan, qinq=args.qinq)
        write_pcap(frames, args.out)
        print(f'已生成 {len(frames)} 帧并写入 {args.out}')
