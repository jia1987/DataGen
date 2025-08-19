import struct
import dpkt

class PcapParser:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def parse(self):
        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            ethernet_frames = []
            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ethernet_frames.append(eth)
            return ethernet_frames

    def extract_payloads(self):
        ethernet_frames = self.parse()
        payloads = []
        for frame in ethernet_frames:
            if isinstance(frame.data, dpkt.ip.IP):
                payloads.append(frame.data.data)
        return payloads