from enum import Enum
import time

# =========================================================
# E1 Frame Modes & Payload Modes
# =========================================================


class FrameMode(Enum):
    UNFRAMED = "unframed"
    FRAMED = "framed"
    CRC4_MULTIFRAME = "crc4_multiframe"


class PayloadMode(Enum):
    ALL_ZERO = "all_zero"
    ALL_ONE = "all_one"
    PRBS = "prbs"


# =========================================================
# PRBS-15 (x^15 + x^14 + 1)
# =========================================================

# Pre-computed PRBS-15 lookup table for byte-level generation
# For each 15-bit state, compute next 8 bits and new state
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
# CRC-4 (ITU-T G.704)
# Polynomial: x^4 + x + 1
# =========================================================

# Pre-computed CRC-4 lookup table for byte-level processing
# Table[crc][byte] = new_crc after processing 8 bits
def _generate_crc4_byte_table():
    poly = 0b0011
    table = []
    for init_crc in range(16):
        row = []
        for byte_val in range(256):
            crc = init_crc
            for bit_idx in range(8):
                bit = (byte_val >> (7 - bit_idx)) & 1
                msb = (crc >> 3) & 1
                crc = ((crc << 1) & 0xF) | bit
                if msb:
                    crc ^= poly
            row.append(crc)
        table.append(tuple(row))
    return tuple(table)


# Pre-computed table for 5-bit processing (TS0 special case)
def _generate_crc4_5bit_table():
    poly = 0b0011
    table = []
    for init_crc in range(16):
        row = []
        for val in range(32):  # 5 bits = 0-31
            crc = init_crc
            for bit_idx in range(5):
                bit = (val >> bit_idx) & 1  # LSB first for TS0
                msb = (crc >> 3) & 1
                crc = ((crc << 1) & 0xF) | bit
                if msb:
                    crc ^= poly
            row.append(crc)
        table.append(tuple(row))
    return tuple(table)


_CRC4_BYTE_TABLE = _generate_crc4_byte_table()
_CRC4_5BIT_TABLE = _generate_crc4_5bit_table()


class CRC4:
    POLY = 0b0011

    @staticmethod
    def compute(bitstream):
        """Original bit-by-bit computation (for compatibility)"""
        crc = 0
        poly = CRC4.POLY
        for bit in bitstream:
            msb = (crc >> 3) & 1
            crc = ((crc << 1) & 0xF) | bit
            if msb:
                crc ^= poly
        return crc & 0xF

    @staticmethod
    def compute_bytes(data, init_crc=0):
        """Optimized byte-level CRC-4 computation using lookup table"""
        crc = init_crc & 0xF
        table = _CRC4_BYTE_TABLE
        for byte in data:
            crc = table[crc][byte]
        return crc

    @staticmethod
    def update_5bits(crc, val):
        """Update CRC with 5-bit value (for TS0 processing)"""
        return _CRC4_5BIT_TABLE[crc][val & 0x1F]

    @staticmethod
    def update_byte(crc, byte_val):
        """Update CRC with single byte"""
        return _CRC4_BYTE_TABLE[crc][byte_val]


# =========================================================
# TS16 CAS（简化：全空闲）
# =========================================================

def generate_cas_ts16(frame_idx):
    return 0x00


# =========================================================
# TS0 构造（统一规范）
# =========================================================

def generate_fas_ts0(sa=1):
    """
    FAS = 0011011
    TS0 = Sa | FAS
    → 0x9B (Sa=1)
    """
    return 0x9B if sa else 0x1B


def generate_mfas_ts0(frame_idx, sa=1, crc_bit=0):
    """
    TS0 (CRC-4 multiframe, non-frame0)
    bit1 : Sa
    bit2~bit5 : MFAS (frame number)
    bit6~bit8 : CRC / E bits
    """
    ts0 = 0
    ts0 |= (sa & 0x01)                # bit1
    ts0 |= ((frame_idx & 0x0F) << 1)  # bit2~bit5
    ts0 |= (crc_bit & 0x07) << 5      # bit6~bit8
    return ts0


# =========================================================
# E1 仿真主类
# =========================================================


class E1FrameSimulator:
    TIMESLOTS = 32
    BYTES_PER_FRAME = 32
    FRAMES_PER_MF = 16

    def __init__(self,
                 frame_mode=FrameMode.FRAMED,
                 payload_mode=PayloadMode.PRBS,
                 sa_bit=1):
        self.frame_mode = frame_mode
        self.payload_mode = payload_mode
        self.sa = sa_bit
        self.prbs = PRBS15()

    # ---------------- Payload ----------------
    def payload_byte(self):
        if self.payload_mode == PayloadMode.ALL_ZERO:
            return 0x00
        elif self.payload_mode == PayloadMode.ALL_ONE:
            return 0xFF
        return self.prbs.next_byte()

    # ---------------- Unframed ----------------
    def generate_unframed(self, frames):
        data = bytearray()
        for _ in range(frames * self.BYTES_PER_FRAME):
            data.append(self.payload_byte())
        return bytes(data)

    # ---------------- Framed ----------------
    def generate_framed(self, frames):
        data = bytearray()
        for _ in range(frames):
            frame = [0] * self.TIMESLOTS
            frame[0] = generate_fas_ts0(self.sa)

            for ts in range(1, self.TIMESLOTS):
                frame[ts] = self.payload_byte()

            data.extend(frame)
        return bytes(data)

    # ---------------- CRC-4 Multiframe ----------------
    def generate_crc4_multiframe(self, multiframe_count):
        stream = bytearray()
        # 缓存查找表引用
        byte_table = _CRC4_BYTE_TABLE
        bit5_table = _CRC4_5BIT_TABLE

        for _ in range(multiframe_count):
            frames = []

            # Step 1: 构造 16 帧（先不填 CRC）
            for idx in range(self.FRAMES_PER_MF):
                frame = [0] * self.TIMESLOTS

                if idx == 0:
                    frame[0] = generate_fas_ts0(self.sa)
                else:
                    frame[0] = generate_mfas_ts0(idx, self.sa, 0)

                frame[16] = generate_cas_ts16(idx)

                for ts in range(1, self.TIMESLOTS):
                    if ts == 16:
                        continue
                    frame[ts] = self.payload_byte()

                frames.append(frame)

            # Step 2: CRC-4 计算（使用查表法优化）
            crc = 0
            for f in frames:
                # TS0: only bit1~bit5 (5 bits), 使用5-bit查找表
                crc = bit5_table[crc][f[0] & 0x1F]
                # TS1-TS31: full 8 bits each, 使用字节查找表
                for ts in range(1, self.TIMESLOTS):
                    crc = byte_table[crc][f[ts]]

            # Step 3: CRC 插入（前 4 帧）
            for i in range(4):
                frames[i][0] |= ((crc >> (3 - i)) & 1) << 5

            # Step 4: 输出
            for f in frames:
                stream.extend(f)

        return bytes(stream)

    # ---------------- Unified API ----------------
    def generate(self, count):
        if self.frame_mode == FrameMode.UNFRAMED:
            return self.generate_unframed(count)
        elif self.frame_mode == FrameMode.FRAMED:
            return self.generate_framed(count)
        elif self.frame_mode == FrameMode.CRC4_MULTIFRAME:
            return self.generate_crc4_multiframe(count)
        else:
            raise ValueError("Unsupported frame mode")


if __name__ == "__main__":
    # Example usage
    simulator = E1FrameSimulator(
        frame_mode=FrameMode.CRC4_MULTIFRAME,
        payload_mode=PayloadMode.PRBS,
        sa_bit=1
    )
    begin_time = time.time()
    e1_data = simulator.generate(10000)  # Generate 10000 frames
    end_time = time.time()
    print(f"Generated E1 Data Length: {len(e1_data)} bytes, Time Taken: {end_time - begin_time:.2f} seconds")
    # Save e1_data to file
    with open("e1_output.dat", "wb") as f:
        f.write(e1_data)
