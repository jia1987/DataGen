"""
ATM Cell Generator - ITU-T I.361/I.363 Standard Implementation

支持的净荷类型:
- AAL5 (IP, PPP, Ethernet)
- AAL1 (CBR voice/video)
- AAL3/4 (SMDS)
- Raw cell payload (PRBS, all-zero, all-one)

参考标准:
- ITU-T I.361: B-ISDN ATM layer specification
- ITU-T I.363: B-ISDN ATM Adaptation Layer (AAL)
- RFC 2684: Multiprotocol Encapsulation over ATM AAL5
"""

from enum import Enum
import struct
import time


# =========================================================
# ATM Constants (ITU-T I.361)
# =========================================================

ATM_CELL_SIZE = 53          # Total cell size in bytes
ATM_HEADER_SIZE = 5         # Header size in bytes
ATM_PAYLOAD_SIZE = 48       # Payload size in bytes

# UNI Header format (ITU-T I.361)
# GFC(4) | VPI(8) | VCI(16) | PT(3) | CLP(1) | HEC(8)

# NNI Header format
# VPI(12) | VCI(16) | PT(3) | CLP(1) | HEC(8)


class ATMCellType(Enum):
    """ATM Cell Types based on PT field"""
    USER_DATA_SDU0 = 0       # User data, SDU-type 0, no congestion
    USER_DATA_SDU0_CONG = 1  # User data, SDU-type 0, congestion
    USER_DATA_SDU1 = 2       # User data, SDU-type 1, no congestion (AAL5 end)
    USER_DATA_SDU1_CONG = 3  # User data, SDU-type 1, congestion
    OAM_F5_SEGMENT = 4       # OAM F5 segment
    OAM_F5_END2END = 5       # OAM F5 end-to-end
    RESOURCE_MGMT = 6        # Resource management
    RESERVED = 7             # Reserved
    
    
class AALType(Enum):
    """AAL Types (ITU-T I.363)"""
    AAL0 = "aal0"           # Raw cells
    AAL1 = "aal1"           # Circuit emulation (CBR)
    AAL2 = "aal2"           # Variable bit rate
    AAL34 = "aal34"         # SMDS
    AAL5 = "aal5"           # Data (IP, PPP, Ethernet)


class PayloadType(Enum):
    """Payload encapsulation types for AAL5"""
    RAW = "raw"             # Raw payload data
    IP = "ip"               # IP packet (RFC 2684 routed)
    PPP = "ppp"             # PPP over AAL5 (RFC 2364)
    ETHERNET = "ethernet"   # Bridged Ethernet (RFC 2684)
    LLC_SNAP = "llc_snap"   # LLC/SNAP encapsulation


class PayloadMode(Enum):
    """Payload fill modes for raw data"""
    ALL_ZERO = "all_zero"
    ALL_ONE = "all_one"
    PRBS = "prbs"
    CUSTOM = "custom"


# =========================================================
# PRBS-15 Generator (optimized with lookup table)
# =========================================================

# Pre-computed PRBS-15 lookup table for byte-level generation
def _generate_prbs15_table():
    """Generate lookup table: state -> (next_byte, new_state)"""
    table = []
    for state in range(0x8000):  # 15-bit states: 0 to 32767
        s = state
        byte_val = 0
        for _ in range(8):
            new_bit = ((s >> 14) ^ (s >> 13)) & 1
            s = ((s << 1) | new_bit) & 0x7FFF
            byte_val = (byte_val << 1) | new_bit
        table.append((byte_val, s))
    return tuple(table)


_PRBS15_TABLE = _generate_prbs15_table()


class PRBS15:
    def __init__(self, seed=0x7FFF):
        self.state = seed & 0x7FFF

    def next_bit(self):
        """Generate single bit (for compatibility)"""
        new_bit = ((self.state >> 14) ^ (self.state >> 13)) & 1
        self.state = ((self.state << 1) | new_bit) & 0x7FFF
        return new_bit

    def next_byte(self):
        """Generate single byte using lookup table"""
        byte_val, self.state = _PRBS15_TABLE[self.state]
        return byte_val

    def next_bytes(self, count):
        """Generate multiple bytes efficiently"""
        result = bytearray(count)
        table = _PRBS15_TABLE
        state = self.state
        for i in range(count):
            byte_val, state = table[state]
            result[i] = byte_val
        self.state = state
        return bytes(result)


# =========================================================
# HEC Calculation (ITU-T I.432)
# Polynomial: x^8 + x^2 + x + 1 (CRC-8)
# =========================================================

# Pre-computed HEC lookup table (generated at module load)
def _generate_hec_table():
    poly = 0x07
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
        table.append(crc)
    return tuple(table)  # tuple for faster indexing


_HEC_TABLE = _generate_hec_table()
_HEC_COSET = 0x55


class HEC:
    """ATM Header Error Control (CRC-8) - optimized with pre-computed table"""

    @staticmethod
    def compute(header_bytes):
        """Compute HEC for 4-byte header (excluding HEC field)"""
        crc = 0
        table = _HEC_TABLE
        for byte in header_bytes[:4]:
            crc = table[crc ^ byte]
        return crc ^ _HEC_COSET


# =========================================================
# CRC-32 for AAL5 (ITU-T I.363.5)
# =========================================================

# Pre-computed CRC-32 lookup table (generated at module load)
def _generate_crc32_table():
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
    return tuple(table)  # tuple for faster indexing


_CRC32_TABLE = _generate_crc32_table()


class CRC32:
    """CRC-32 for AAL5 trailer - optimized with pre-computed table"""

    @staticmethod
    def compute(data):
        """Compute CRC-32 for AAL5 CPCS-PDU"""
        crc = 0xFFFFFFFF
        table = _CRC32_TABLE
        for byte in data:
            crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
        return crc ^ 0xFFFFFFFF

    @staticmethod
    def compute_fast(data):
        """Optimized CRC-32 using memoryview for large data"""
        crc = 0xFFFFFFFF
        table = _CRC32_TABLE
        if isinstance(data, (bytes, bytearray)):
            mv = memoryview(data)
            for byte in mv:
                crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
        else:
            for byte in data:
                crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
        return crc ^ 0xFFFFFFFF


# =========================================================
# ATM Header Builder
# =========================================================

class ATMHeader:
    """ATM Cell Header (UNI/NNI format)"""

    def __init__(self, vpi=0, vci=32, pt=0, clp=0, gfc=0, is_uni=True):
        self.gfc = gfc & 0x0F      # Generic Flow Control (UNI only)
        self.vpi = vpi & 0xFF if is_uni else vpi & 0xFFF
        self.vci = vci & 0xFFFF
        self.pt = pt & 0x07        # Payload Type
        self.clp = clp & 0x01      # Cell Loss Priority
        self.is_uni = is_uni

    def to_bytes(self):
        """Build 5-byte ATM header with HEC"""
        if self.is_uni:
            # UNI format: GFC(4) | VPI(8) | VCI(16) | PT(3) | CLP(1) | HEC(8)
            b0 = (self.gfc << 4) | (self.vpi >> 4)
            b1 = ((self.vpi & 0x0F) << 4) | (self.vci >> 12)
            b2 = (self.vci >> 4) & 0xFF
            b3 = ((self.vci & 0x0F) << 4) | (self.pt << 1) | self.clp
        else:
            # NNI format: VPI(12) | VCI(16) | PT(3) | CLP(1) | HEC(8)
            b0 = (self.vpi >> 4) & 0xFF
            b1 = ((self.vpi & 0x0F) << 4) | (self.vci >> 12)
            b2 = (self.vci >> 4) & 0xFF
            b3 = ((self.vci & 0x0F) << 4) | (self.pt << 1) | self.clp

        header = bytes([b0, b1, b2, b3])
        hec = HEC.compute(header)
        return header + bytes([hec])


# =========================================================
# AAL5 CPCS-PDU Builder (ITU-T I.363.5)
# =========================================================

class AAL5Builder:
    """AAL5 Common Part Convergence Sublayer"""

    # LLC/SNAP Headers (RFC 2684)
    LLC_SNAP_IP = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00])
    LLC_SNAP_PPP = bytes([0xFE, 0xFE, 0x03, 0xCF])
    LLC_SNAP_ETH = bytes([0xAA, 0xAA, 0x03, 0x00, 0x80, 0xC2, 0x00, 0x07])

    @staticmethod
    def build_cpcs_pdu(payload, cpcs_uu=0, cpi=0):
        """
        Build AAL5 CPCS-PDU with trailer

        Trailer format (8 bytes):
        - CPCS-UU (1 byte): User-to-user indication
        - CPI (1 byte): Common Part Indicator
        - Length (2 bytes): Payload length
        - CRC-32 (4 bytes): CRC of padded payload + trailer (excl CRC)
        """
        payload_len = len(payload)

        # Calculate padding to make total PDU multiple of 48 bytes
        # PDU = payload + pad + 8-byte trailer
        total_without_pad = payload_len + 8
        pad_len = (48 - (total_without_pad % 48)) % 48

        # Build PDU without CRC
        pad = bytes(pad_len)
        trailer_without_crc = struct.pack(">BBH", cpcs_uu, cpi, payload_len)

        pdu_without_crc = payload + pad + trailer_without_crc

        # Compute CRC-32 and append
        crc = CRC32.compute(pdu_without_crc)
        # CRC is transmitted in little-endian order per I.363.5
        crc_bytes = struct.pack("<I", crc)

        return pdu_without_crc + crc_bytes

    @classmethod
    def encapsulate_ip(cls, ip_packet):
        """Encapsulate IP packet with LLC/SNAP (RFC 2684)"""
        return cls.build_cpcs_pdu(cls.LLC_SNAP_IP + ip_packet)

    @classmethod
    def encapsulate_ppp(cls, ppp_frame):
        """Encapsulate PPP frame (RFC 2364)"""
        return cls.build_cpcs_pdu(cls.LLC_SNAP_PPP + ppp_frame)

    @classmethod
    def encapsulate_ethernet(cls, eth_frame):
        """Encapsulate Ethernet frame (RFC 2684 bridged)"""
        # Pad field (2 bytes) + Ethernet frame
        pad = bytes([0x00, 0x00])
        return cls.build_cpcs_pdu(cls.LLC_SNAP_ETH + pad + eth_frame)


# =========================================================
# AAL1 Builder (ITU-T I.363.1)
# =========================================================

class AAL1Builder:
    """AAL1 for Circuit Emulation Service"""

    def __init__(self, structured=False):
        self.structured = structured
        self.sequence_number = 0

    def build_cell_payload(self, user_data):
        """
        Build AAL1 cell payload with SAR-PDU header

        SAR-PDU format:
        - CSI (1 bit): Convergence Sublayer Indication
        - SC (3 bits): Sequence Count
        - CRC (3 bits): CRC of CSI+SC
        - Parity (1 bit): Even parity of header
        - SAR-PDU payload (47 bytes)
        """
        if len(user_data) > 47:
            user_data = user_data[:47]
        elif len(user_data) < 47:
            user_data = user_data + bytes(47 - len(user_data))

        # Build SAR-PDU header
        csi = 1 if self.structured else 0
        sc = self.sequence_number & 0x07

        # CRC-3 of CSI + SC (simplified)
        crc = ((csi << 3) | sc) & 0x07

        # Calculate parity
        header_bits = (csi << 7) | (sc << 4) | (crc << 1)
        parity = bin(header_bits).count('1') % 2

        sar_header = (csi << 7) | (sc << 4) | (crc << 1) | parity

        self.sequence_number = (self.sequence_number + 1) % 8

        return bytes([sar_header]) + user_data


# =========================================================
# AAL3/4 Builder (ITU-T I.363.3/4)
# =========================================================

class AAL34Builder:
    """AAL3/4 for SMDS and Frame Relay"""

    def __init__(self, mid=0):
        self.mid = mid & 0x3FF  # Message ID (10 bits)
        self.sequence_number = 0

    def build_cell_payload(self, user_data, segment_type='continuation'):
        """
        Build AAL3/4 SAR-PDU

        SAR-PDU format (48 bytes):
        - ST (2 bits): Segment Type (BOM=2, COM=0, EOM=1, SSM=3)
        - SN (4 bits): Sequence Number
        - MID (10 bits): Multiplex ID
        - Payload (44 bytes)
        - LI (6 bits): Length Indicator
        - CRC-10 (10 bits)
        """
        st_values = {'begin': 2, 'continuation': 0, 'end': 1, 'single': 3}
        st = st_values.get(segment_type, 0)

        sn = self.sequence_number & 0x0F
        self.sequence_number = (self.sequence_number + 1) % 16

        # Limit payload to 44 bytes
        if len(user_data) > 44:
            user_data = user_data[:44]
        li = len(user_data)
        user_data = user_data + bytes(44 - len(user_data))

        # Build header (2 bytes)
        header = (st << 14) | (sn << 10) | self.mid
        header_bytes = struct.pack(">H", header)

        # Build trailer (2 bytes): LI(6) + CRC-10
        # Simplified CRC-10
        trailer_data = header_bytes + user_data + bytes([li << 2])
        crc10 = sum(trailer_data) & 0x3FF
        trailer = (li << 10) | crc10
        trailer_bytes = struct.pack(">H", trailer)

        return header_bytes + user_data + trailer_bytes


# =========================================================
# Sample Payload Generators
# =========================================================

class PayloadGenerator:
    """Generate sample payloads for testing"""

    @staticmethod
    def generate_ip_packet(src_ip="192.168.1.1", dst_ip="192.168.1.2",
                           payload_size=64, protocol=17):
        """Generate a simple IP packet (UDP by default)"""
        def ip_to_bytes(ip):
            return bytes(int(x) for x in ip.split('.'))

        # IP Header (20 bytes minimum)
        version_ihl = 0x45  # IPv4, 5 words (20 bytes)
        dscp_ecn = 0x00
        total_length = 20 + 8 + payload_size  # IP + UDP + payload
        identification = 0x1234
        flags_frag = 0x4000  # Don't fragment
        ttl = 64
        proto = protocol  # UDP=17, TCP=6
        checksum = 0  # Simplified

        header = struct.pack(">BBHHHBBH",
                             version_ihl, dscp_ecn, total_length,
                             identification, flags_frag,
                             ttl, proto, checksum)
        header += ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)

        # UDP Header (8 bytes)
        src_port = 12345
        dst_port = 80
        udp_length = 8 + payload_size
        udp_checksum = 0
        udp_header = struct.pack(">HHHH", src_port, dst_port,
                                 udp_length, udp_checksum)

        # Payload
        payload = bytes(range(payload_size % 256)) * (payload_size // 256 + 1)
        payload = payload[:payload_size]

        return header + udp_header + payload

    @staticmethod
    def generate_ppp_frame(protocol=0x0021, payload_size=64):
        """Generate PPP frame (IP payload by default)"""
        # PPP Header
        address = 0xFF
        control = 0x03
        proto = protocol  # 0x0021 = IP

        header = struct.pack(">BBH", address, control, proto)

        # Payload
        payload = bytes([i % 256 for i in range(payload_size)])

        return header + payload

    @staticmethod
    def generate_ethernet_frame(src_mac="00:11:22:33:44:55",
                                dst_mac="66:77:88:99:AA:BB",
                                ethertype=0x0800, payload_size=46):
        """Generate Ethernet frame"""
        def mac_to_bytes(mac):
            return bytes(int(x, 16) for x in mac.split(':'))

        dst = mac_to_bytes(dst_mac)
        src = mac_to_bytes(src_mac)
        etype = struct.pack(">H", ethertype)

        payload = bytes([i % 256 for i in range(payload_size)])

        return dst + src + etype + payload


# =========================================================
# ATM Cell Simulator
# =========================================================

class ATMCellSimulator:
    """ATM Cell Generator supporting multiple AAL types"""

    def __init__(self, vpi=0, vci=32, is_uni=True,
                 aal_type=AALType.AAL5,
                 payload_mode=PayloadMode.PRBS):
        self.vpi = vpi
        self.vci = vci
        self.is_uni = is_uni
        self.aal_type = aal_type
        self.payload_mode = payload_mode
        self.prbs = PRBS15()
        self.aal1 = AAL1Builder()
        self.aal34 = AAL34Builder()

    def _fill_payload(self, size):
        """Generate fill payload based on mode"""
        if self.payload_mode == PayloadMode.ALL_ZERO:
            return bytes(size)
        elif self.payload_mode == PayloadMode.ALL_ONE:
            return bytes([0xFF] * size)
        else:
            return self.prbs.next_bytes(size)

    def generate_raw_cells(self, count):
        """Generate raw ATM cells with PRBS/pattern payload"""
        cells = bytearray()
        for _ in range(count):
            header = ATMHeader(self.vpi, self.vci, pt=0, is_uni=self.is_uni)
            payload = self._fill_payload(ATM_PAYLOAD_SIZE)
            cells.extend(header.to_bytes() + payload)
        return bytes(cells)

    def generate_aal1_cells(self, user_data):
        """Generate AAL1 cells for CBR traffic"""
        cells = bytearray()
        offset = 0
        while offset < len(user_data):
            chunk = user_data[offset:offset + 47]
            if len(chunk) < 47:
                chunk = chunk + self._fill_payload(47 - len(chunk))

            payload = self.aal1.build_cell_payload(chunk)
            header = ATMHeader(self.vpi, self.vci, pt=0, is_uni=self.is_uni)
            cells.extend(header.to_bytes() + payload)
            offset += 47

        return bytes(cells)

    def generate_aal34_cells(self, user_data):
        """Generate AAL3/4 cells"""
        cells = bytearray()
        offset = 0
        total_len = len(user_data)

        while offset < total_len:
            remaining = total_len - offset
            chunk = user_data[offset:offset + 44]

            if offset == 0 and remaining <= 44:
                seg_type = 'single'
            elif offset == 0:
                seg_type = 'begin'
            elif remaining <= 44:
                seg_type = 'end'
            else:
                seg_type = 'continuation'

            payload = self.aal34.build_cell_payload(chunk, seg_type)
            header = ATMHeader(self.vpi, self.vci, pt=0, is_uni=self.is_uni)
            cells.extend(header.to_bytes() + payload)
            offset += 44

        return bytes(cells)

    def generate_aal5_cells(self, cpcs_pdu):
        """Segment AAL5 CPCS-PDU into ATM cells"""
        cells = bytearray()
        num_cells = len(cpcs_pdu) // ATM_PAYLOAD_SIZE

        for i in range(num_cells):
            segment = cpcs_pdu[i * ATM_PAYLOAD_SIZE:(i + 1) * ATM_PAYLOAD_SIZE]
            # Last cell has PT=1 (AAL5 end indication)
            pt = 1 if i == num_cells - 1 else 0
            header = ATMHeader(self.vpi, self.vci, pt=pt, is_uni=self.is_uni)
            cells.extend(header.to_bytes() + segment)

        return bytes(cells)

    def generate_ip_over_aal5(self, ip_packet):
        """Generate ATM cells for IP over AAL5"""
        cpcs_pdu = AAL5Builder.encapsulate_ip(ip_packet)
        return self.generate_aal5_cells(cpcs_pdu)

    def generate_ppp_over_aal5(self, ppp_frame):
        """Generate ATM cells for PPPoA"""
        cpcs_pdu = AAL5Builder.encapsulate_ppp(ppp_frame)
        return self.generate_aal5_cells(cpcs_pdu)

    def generate_ethernet_over_aal5(self, eth_frame):
        """Generate ATM cells for Ethernet over AAL5"""
        cpcs_pdu = AAL5Builder.encapsulate_ethernet(eth_frame)
        return self.generate_aal5_cells(cpcs_pdu)

    # =========================================================
    # Import External Data Interfaces
    # =========================================================

    def import_ip_packets(self, packets):
        """
        Import external IP packets and convert to ATM cells

        Args:
            packets: List of IP packets (bytes) or single packet

        Returns:
            ATM cells containing all IP packets
        """
        if isinstance(packets, bytes):
            packets = [packets]

        result = bytearray()
        for pkt in packets:
            result.extend(self.generate_ip_over_aal5(pkt))
        return bytes(result)

    def import_ppp_frames(self, frames):
        """
        Import external PPP frames and convert to ATM cells

        Args:
            frames: List of PPP frames (bytes) or single frame

        Returns:
            ATM cells containing all PPP frames
        """
        if isinstance(frames, bytes):
            frames = [frames]

        result = bytearray()
        for frame in frames:
            result.extend(self.generate_ppp_over_aal5(frame))
        return bytes(result)

    def import_ethernet_frames(self, frames):
        """
        Import external Ethernet frames and convert to ATM cells

        Args:
            frames: List of Ethernet frames (bytes) or single frame

        Returns:
            ATM cells containing all Ethernet frames
        """
        if isinstance(frames, bytes):
            frames = [frames]

        result = bytearray()
        for frame in frames:
            result.extend(self.generate_ethernet_over_aal5(frame))
        return bytes(result)

    def import_raw_data(self, data, encap_type=PayloadType.RAW):
        """
        Import raw data with specified encapsulation type

        Args:
            data: Raw bytes data
            encap_type: Encapsulation type (RAW, IP, PPP, ETHERNET)

        Returns:
            ATM cells
        """
        if encap_type == PayloadType.IP:
            return self.import_ip_packets(data)
        elif encap_type == PayloadType.PPP:
            return self.import_ppp_frames(data)
        elif encap_type == PayloadType.ETHERNET:
            return self.import_ethernet_frames(data)
        else:
            # Raw AAL5 encapsulation
            cpcs_pdu = AAL5Builder.build_cpcs_pdu(data)
            return self.generate_aal5_cells(cpcs_pdu)

    def import_from_file(self, filepath, payload_type=PayloadType.RAW,
                         packet_size=None, has_length_header=False):
        """
        Import data from file and convert to ATM cells

        Args:
            filepath: Path to the data file
            payload_type: Type of payload (IP, PPP, ETHERNET, RAW)
            packet_size: Fixed packet size (if None, read whole file as one packet)
            has_length_header: If True, each packet has 2-byte length prefix

        Returns:
            ATM cells
        """
        with open(filepath, 'rb') as f:
            file_data = f.read()

        packets = []

        if has_length_header:
            # Parse packets with 2-byte length prefix
            offset = 0
            while offset + 2 <= len(file_data):
                pkt_len = struct.unpack(">H", file_data[offset:offset + 2])[0]
                offset += 2
                if offset + pkt_len <= len(file_data):
                    packets.append(file_data[offset:offset + pkt_len])
                    offset += pkt_len
                else:
                    break
        elif packet_size:
            # Fixed size packets
            for i in range(0, len(file_data), packet_size):
                pkt = file_data[i:i + packet_size]
                if len(pkt) == packet_size:
                    packets.append(pkt)
        else:
            # Single packet (whole file)
            packets = [file_data]

        if payload_type == PayloadType.IP:
            return self.import_ip_packets(packets)
        elif payload_type == PayloadType.PPP:
            return self.import_ppp_frames(packets)
        elif payload_type == PayloadType.ETHERNET:
            return self.import_ethernet_frames(packets)
        else:
            result = bytearray()
            for pkt in packets:
                cpcs_pdu = AAL5Builder.build_cpcs_pdu(pkt)
                result.extend(self.generate_aal5_cells(cpcs_pdu))
            return bytes(result)

    def import_from_pcap(self, filepath, payload_type=PayloadType.ETHERNET):
        """
        Import packets from PCAP file

        Args:
            filepath: Path to PCAP file
            payload_type: How to treat packets (ETHERNET, IP, RAW)

        Returns:
            ATM cells

        Note: Requires pcap file in standard libpcap format
        """
        with open(filepath, 'rb') as f:
            # Read PCAP global header (24 bytes)
            global_header = f.read(24)
            if len(global_header) < 24:
                raise ValueError("Invalid PCAP file: too short")

            magic = struct.unpack("<I", global_header[0:4])[0]
            if magic == 0xA1B2C3D4:
                byte_order = "<"  # Little endian
            elif magic == 0xD4C3B2A1:
                byte_order = ">"  # Big endian
            else:
                raise ValueError(f"Invalid PCAP magic: {hex(magic)}")

            packets = []

            # Read packets
            while True:
                # Packet header (16 bytes)
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    byte_order + "IIII", pkt_header)

                # Packet data
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                packets.append(pkt_data)

        if payload_type == PayloadType.ETHERNET:
            return self.import_ethernet_frames(packets)
        elif payload_type == PayloadType.IP:
            # Skip Ethernet header (14 bytes) to get IP
            ip_packets = []
            for pkt in packets:
                if len(pkt) > 14:
                    ip_packets.append(pkt[14:])
            return self.import_ip_packets(ip_packets)
        else:
            result = bytearray()
            for pkt in packets:
                cpcs_pdu = AAL5Builder.build_cpcs_pdu(pkt)
                result.extend(self.generate_aal5_cells(cpcs_pdu))
            return bytes(result)

    def generate(self, payload_type=PayloadType.RAW, count=1, **kwargs):
        """
        Unified generation API

        Args:
            payload_type: Type of payload to generate
            count: Number of packets/frames/cells to generate
            **kwargs: Additional parameters for specific payload types
        """
        result = bytearray()

        for _ in range(count):
            if payload_type == PayloadType.RAW:
                if self.aal_type == AALType.AAL0:
                    result.extend(self.generate_raw_cells(1))
                elif self.aal_type == AALType.AAL1:
                    data = self._fill_payload(kwargs.get('size', 47))
                    result.extend(self.generate_aal1_cells(data))
                elif self.aal_type == AALType.AAL34:
                    data = self._fill_payload(kwargs.get('size', 44))
                    result.extend(self.generate_aal34_cells(data))
                else:
                    data = self._fill_payload(kwargs.get('size', 64))
                    cpcs = AAL5Builder.build_cpcs_pdu(data)
                    result.extend(self.generate_aal5_cells(cpcs))

            elif payload_type == PayloadType.IP:
                ip_pkt = PayloadGenerator.generate_ip_packet(
                    src_ip=kwargs.get('src_ip', '192.168.1.1'),
                    dst_ip=kwargs.get('dst_ip', '192.168.1.2'),
                    payload_size=kwargs.get('size', 64)
                )
                result.extend(self.generate_ip_over_aal5(ip_pkt))

            elif payload_type == PayloadType.PPP:
                ppp_frame = PayloadGenerator.generate_ppp_frame(
                    payload_size=kwargs.get('size', 64)
                )
                result.extend(self.generate_ppp_over_aal5(ppp_frame))

            elif payload_type == PayloadType.ETHERNET:
                eth_frame = PayloadGenerator.generate_ethernet_frame(
                    payload_size=kwargs.get('size', 64)
                )
                result.extend(self.generate_ethernet_over_aal5(eth_frame))

            elif payload_type == PayloadType.LLC_SNAP:
                data = kwargs.get('data', self._fill_payload(64))
                cpcs = AAL5Builder.build_cpcs_pdu(
                    AAL5Builder.LLC_SNAP_IP + data
                )
                result.extend(self.generate_aal5_cells(cpcs))

        return bytes(result)


# =========================================================
# OAM Cell Generator (ITU-T I.610)
# =========================================================

class OAMCellGenerator:
    """Generate OAM cells for ATM network management"""

    @staticmethod
    def generate_f5_loopback(vpi, vci, loopback_id=1, is_segment=True):
        """Generate F5 OAM Loopback cell"""
        pt = 4 if is_segment else 5

        # OAM cell payload (48 bytes)
        oam_type = 0x18  # Loopback
        function_type = 0x01
        correlation_tag = struct.pack(">I", loopback_id)
        location_id = bytes(16)  # All zeros
        source_id = bytes(16)
        reserved = bytes(8)
        crc10 = bytes(2)  # Simplified

        payload = bytes([oam_type, function_type]) + correlation_tag
        payload += location_id + source_id + reserved
        payload = payload[:46] + crc10

        header = ATMHeader(vpi, vci, pt=pt)
        return header.to_bytes() + payload

    @staticmethod
    def generate_ais(vpi, vci, is_segment=True):
        """Generate Alarm Indication Signal cell"""
        pt = 4 if is_segment else 5
        oam_type = 0x10  # Fault Management
        function_type = 0x00  # AIS

        payload = bytes([oam_type, function_type]) + bytes(46)

        header = ATMHeader(vpi, vci, pt=pt)
        return header.to_bytes() + payload


# =========================================================
# Utility Functions
# =========================================================

def print_cell_hex(cell_data, cells_per_line=1):
    """Pretty print ATM cells in hex format"""
    cell_count = len(cell_data) // ATM_CELL_SIZE
    for i in range(cell_count):
        cell = cell_data[i * ATM_CELL_SIZE:(i + 1) * ATM_CELL_SIZE]
        header = cell[:5]
        payload = cell[5:]

        print(f"Cell {i}:")
        print(f"  Header: {header.hex().upper()}")
        print(f"  Payload: {payload[:16].hex().upper()}...")
        if (i + 1) % cells_per_line == 0:
            print()


def parse_atm_header(header_bytes, is_uni=True):
    """Parse ATM header and return fields"""
    if len(header_bytes) < 5:
        raise ValueError("Header must be at least 5 bytes")

    b = header_bytes
    if is_uni:
        gfc = (b[0] >> 4) & 0x0F
        vpi = ((b[0] & 0x0F) << 4) | ((b[1] >> 4) & 0x0F)
    else:
        gfc = 0
        vpi = ((b[0] & 0xFF) << 4) | ((b[1] >> 4) & 0x0F)

    vci = ((b[1] & 0x0F) << 12) | (b[2] << 4) | ((b[3] >> 4) & 0x0F)
    pt = (b[3] >> 1) & 0x07
    clp = b[3] & 0x01
    hec = b[4]

    return {
        'gfc': gfc,
        'vpi': vpi,
        'vci': vci,
        'pt': pt,
        'clp': clp,
        'hec': hec
    }


# =========================================================
# Main Entry
# =========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("ATM Cell Generator - ITU-T I.361/I.363")
    print("=" * 60)

    # Example 1: Raw ATM cells with PRBS
    print("\n[1] Generating raw ATM cells with PRBS payload...")
    sim = ATMCellSimulator(vpi=0, vci=100, aal_type=AALType.AAL0)
    raw_cells = sim.generate_raw_cells(5)
    print(f"Generated {len(raw_cells)} bytes ({len(raw_cells) // 53} cells)")
    print_cell_hex(raw_cells)

    # Example 2: IP over AAL5
    print("\n[2] Generating IP packet over AAL5...")
    sim = ATMCellSimulator(vpi=0, vci=32, aal_type=AALType.AAL5)
    ip_pkt = PayloadGenerator.generate_ip_packet(payload_size=100)
    ip_cells = sim.generate_ip_over_aal5(ip_pkt)
    print(f"IP packet size: {len(ip_pkt)} bytes")
    print(f"Generated {len(ip_cells)} bytes ({len(ip_cells) // 53} cells)")
    print_cell_hex(ip_cells)

    # Example 3: PPP over AAL5
    print("\n[3] Generating PPP frame over AAL5...")
    ppp_frame = PayloadGenerator.generate_ppp_frame(payload_size=50)
    ppp_cells = sim.generate_ppp_over_aal5(ppp_frame)
    print(f"PPP frame size: {len(ppp_frame)} bytes")
    print(f"Generated {len(ppp_cells)} bytes ({len(ppp_cells) // 53} cells)")

    # Example 4: Ethernet over AAL5
    print("\n[4] Generating Ethernet frame over AAL5...")
    eth_frame = PayloadGenerator.generate_ethernet_frame(payload_size=64)
    eth_cells = sim.generate_ethernet_over_aal5(eth_frame)
    print(f"Ethernet frame size: {len(eth_frame)} bytes")
    print(f"Generated {len(eth_cells)} bytes ({len(eth_cells) // 53} cells)")

    # Example 5: AAL1 cells (CBR)
    print("\n[5] Generating AAL1 cells for CBR traffic...")
    sim_aal1 = ATMCellSimulator(vpi=1, vci=50, aal_type=AALType.AAL1)
    cbr_data = bytes(range(256)) * 2  # 512 bytes
    aal1_cells = sim_aal1.generate_aal1_cells(cbr_data)
    print(f"CBR data size: {len(cbr_data)} bytes")
    print(f"Generated {len(aal1_cells)} bytes ({len(aal1_cells) // 53} cells)")

    # Example 6: OAM cells
    print("\n[6] Generating OAM Loopback cell...")
    oam_cell = OAMCellGenerator.generate_f5_loopback(0, 32)
    print_cell_hex(oam_cell)

    # Example 7: Unified API
    print("\n[7] Using unified generate() API...")
    sim = ATMCellSimulator(vpi=0, vci=35)
    begin_time = time.time()
    data = sim.generate(PayloadType.IP, count=10000, size=100)
    end_time = time.time()
    print(f"Generated {len(data)} bytes, Time: {end_time - begin_time:.3f}s")

    # =========================================================
    # Example 8-11: Import External Data Interfaces
    # =========================================================

    print("\n" + "=" * 60)
    print("Import External Data Interfaces Demo")
    print("=" * 60)

    # Example 8: Import external IP packets
    print("\n[8] Importing external IP packets...")
    sim = ATMCellSimulator(vpi=0, vci=32)

    # Simulate external IP packets (e.g., from another tool or capture)
    external_ip_packets = [
        PayloadGenerator.generate_ip_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", payload_size=100),
        PayloadGenerator.generate_ip_packet(
            src_ip="10.0.0.3", dst_ip="10.0.0.4", payload_size=200),
        PayloadGenerator.generate_ip_packet(
            src_ip="10.0.0.5", dst_ip="10.0.0.6", payload_size=1400),
    ]
    ip_atm_cells = sim.import_ip_packets(external_ip_packets)
    print(f"Imported {len(external_ip_packets)} IP packets")
    print(f"Generated {len(ip_atm_cells)} bytes ({len(ip_atm_cells) // 53} cells)")

    # Example 9: Import external PPP frames
    print("\n[9] Importing external PPP frames...")
    external_ppp_frames = [
        PayloadGenerator.generate_ppp_frame(protocol=0x0021, payload_size=64),
        PayloadGenerator.generate_ppp_frame(protocol=0x8021, payload_size=32),  # IPCP
    ]
    ppp_atm_cells = sim.import_ppp_frames(external_ppp_frames)
    print(f"Imported {len(external_ppp_frames)} PPP frames")
    print(f"Generated {len(ppp_atm_cells)} bytes ({len(ppp_atm_cells) // 53} cells)")

    # Example 10: Import external Ethernet frames
    print("\n[10] Importing external Ethernet frames...")
    external_eth_frames = [
        PayloadGenerator.generate_ethernet_frame(
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:AA:BB",
            ethertype=0x0800,  # IPv4
            payload_size=100),
        PayloadGenerator.generate_ethernet_frame(
            src_mac="AA:BB:CC:DD:EE:FF",
            dst_mac="FF:FF:FF:FF:FF:FF",  # Broadcast
            ethertype=0x0806,  # ARP
            payload_size=28),
    ]
    eth_atm_cells = sim.import_ethernet_frames(external_eth_frames)
    print(f"Imported {len(external_eth_frames)} Ethernet frames")
    print(f"Generated {len(eth_atm_cells)} bytes ({len(eth_atm_cells) // 53} cells)")

    # Example 11: Import raw data with encapsulation
    print("\n[11] Importing raw data with different encapsulations...")
    raw_data = bytes([0x45, 0x00, 0x00, 0x28] + [0x00] * 36)  # Minimal IP header
    cells = sim.import_raw_data(raw_data, encap_type=PayloadType.IP)
    print(f"Raw data size: {len(raw_data)} bytes")
    print(f"Generated {len(cells)} bytes ({len(cells) // 53} cells)")

    # Example 12: Create sample file and import
    print("\n[12] Importing from file (demo with temp file)...")
    import tempfile
    import os

    # Create temp file with sample IP packets (with length headers)
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
        tmp_path = tmp.name
        # Write packets with 2-byte length prefix
        for i in range(5):
            pkt = PayloadGenerator.generate_ip_packet(payload_size=50 + i * 20)
            tmp.write(struct.pack(">H", len(pkt)))
            tmp.write(pkt)

    # Import from file
    cells = sim.import_from_file(tmp_path, payload_type=PayloadType.IP,
                                has_length_header=True)
    print(f"Imported packets from file: {tmp_path}")
    print(f"Generated {len(cells)} bytes ({len(cells) // 53} cells)")
    os.unlink(tmp_path)

    # Summary
    print("\n" + "=" * 60)
    print("Import Interface Summary:")
    print("=" * 60)
    print("""
    sim.import_ip_packets(packets)       - Import IP packet list
    sim.import_ppp_frames(frames)        - Import PPP frame list
    sim.import_ethernet_frames(frames)   - Import Ethernet frame list
    sim.import_raw_data(data, encap)     - Import raw data with encap type
    sim.import_from_file(path, type)     - Import from binary file
    sim.import_from_pcap(path, type)     - Import from PCAP file
    """)

    # Save to file
    with open("atm_output.dat", "wb") as f:
        f.write(data)
    print("Saved to atm_output.dat")
