
"""
This module mimics how Whisper parses packets using the
pcapng python package. 
"""

import sys, os
import pdb

import argparse
import heapq

from pcapng import FileScanner
from pcapng import blocks
from pcapng import utils

class IPFormatError(Exception):
    pass

class IPv4Header:
    """
    Parses IPv4 packets based on RFC 791.
    Apparently IP header starts at byte 14.
    """
    ETH_II_TYPE_OFF = 12
    ETH_II_TYPE_LEN = 2
    IPV4_MAGIC_NUM = 0x0800
    
    IP_HEAD_OFF = 14      # Offset of IPv4 header in bytes
    
    LENGTH_OFF = 2 + IP_HEAD_OFF        # Offset in bytes
    LENGTH_LEN = 2                      # Length in bytes
    FRAG_OFF = 6 + IP_HEAD_OFF
    FRAG_LEN = 2
    PROTO_OFF = 9 + IP_HEAD_OFF
    PROTO_LEN = 1
    SRC_OFF = 12 + IP_HEAD_OFF
    SRC_LEN = 4
    DEST_OFF = 16 + IP_HEAD_OFF
    DEST_LEN = 4
    IHL_OFF = 0 + IP_HEAD_OFF
    IHL_LEN = 1
    IHL_MASK = 0xf           # Need to get the four lower bits
    VERSION_MASK = 0xf0

    TCP_MAGIC_NUM = 6
    UDP_MAGIC_NUM = 17

    TCP_CONTROL_OFF = 13
    TCP_FIN_MASK = 0x01
    TCP_SYN_MASK = 0x02
    TCP_RST_MASK = 0x04
    # No urg ack or push mask

    IGMP_MASK = -1
    ICMP_MASK = -1
    
    
    def __init__(self, total_length, src_addr, dest_addr, protocol,
                 header_length, is_fragment, proto_type=None):
        
        self.total_length = total_length
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.protocol = protocol
        self.protocol_type = proto_type
        self.header_length = header_length;
        self.is_fragment = is_fragment
        #if self.protocol_type is not None:
        if False:
            print("IPv4/{:s}/{:s}; Length: {:7d}; {:s} -> {:s}".format(
                self.protocol,
                (self.protocol_type if self.protocol_type else "unk"),
                self.total_length,
                utils.unpack_ipv4(self.src_addr),
                utils.unpack_ipv4(self.dest_addr),
            ))

            

    @classmethod
    def from_packet(cls, packet_data):
        """
        Produce the IPv4 header from raw packet data
        """
        if len(packet_data) < 20:
            raise IPFormatError(
                "Packet consists of less than 20 bytes")

        frag_end = cls.FRAG_OFF + cls.FRAG_LEN
        frag_bytes = int.from_bytes(
            packet_data[cls.FRAG_OFF:frag_end], "big")
        is_fragment = False
        if frag_bytes & 0x3fff > 0:
            is_fragment = True

        eth2type_end = cls.ETH_II_TYPE_OFF + cls.ETH_II_TYPE_LEN
        eth_2_ethertype = int.from_bytes(
            packet_data[cls.ETH_II_TYPE_OFF:eth2type_end], "big")
        if eth_2_ethertype != cls.IPV4_MAGIC_NUM:
            #print("{:x}".format(eth_2_ethertype))
            raise IPFormatError("Not IPv4 or not Ethernet II.")
        
        ihl_end = cls.IHL_OFF + cls.IHL_LEN
        ihl = int.from_bytes(packet_data[cls.IHL_OFF:ihl_end], "big")
        ihl &= cls.IHL_MASK

        if (ihl < 5) or (ihl > 15):
            raise IPFormatError(
                "Packet header has invalid length: {:d}".format(ihl))

        total_len_end = cls.LENGTH_OFF + cls.LENGTH_LEN
        total_len = int.from_bytes(
            packet_data[cls.LENGTH_OFF:total_len_end], "big")
        src_addr_end = cls.SRC_OFF + cls.SRC_LEN
        src_addr = packet_data[cls.SRC_OFF:src_addr_end]
        dest_addr_end = cls.DEST_OFF + cls.DEST_LEN
        dest_addr = packet_data[cls.DEST_OFF:dest_addr_end]
        protocol_end = cls.PROTO_OFF + cls.PROTO_LEN
        protocol = int.from_bytes(
            packet_data[cls.PROTO_OFF:protocol_end], "big")
        proto_str = "other"

        proto_type = None
        if protocol == cls.TCP_MAGIC_NUM: # Make sure this actually works
            proto_str = "tcp"
            tcp_start = cls.IP_HEAD_OFF + (ihl * 4)
            control_byte_start = tcp_start + cls.TCP_CONTROL_OFF
            if control_byte_start >= len(packet_data):
                print(packet_data)
                raise IPFormatError("packet_data too small for control byte")
            tcp_flags = packet_data[control_byte_start]
            if (tcp_flags & cls.TCP_FIN_MASK) > 0:
                proto_type = "fin"
            elif (tcp_flags & cls.TCP_SYN_MASK) > 0:
                proto_type = "syn"
            elif (tcp_flags & cls.TCP_RST_MASK) > 0:
                proto_type = "rst"
        elif protocol == cls.UDP_MAGIC_NUM:
            proto_str = "udp"
        else:
            proto_str = "unknown"
            
        return cls(total_length=total_len,
                   src_addr=src_addr,
                   dest_addr=dest_addr,
                   protocol=proto_str,
                   header_length=ihl,
                   is_fragment=is_fragment,
                   proto_type=proto_type)


def get_labels(label_file):
    """
    Reads in labels while taking into account that they might
    be one or two columns. First column doesn't matter if they
    are two columns
    """
    with open(label_file, "r") as fin:
        label_lines = fin.read().strip().split("\n")

    if len(label_lines) <= 0:
        raise ValueError("Labels are empty")

    if len(label_lines[0].split(",")) > 1:
        labels = [int(l.split(",")[1].strip()) for l in label_lines[1:]]
    else:
        labels = [int(l.strip()) for l in label_lines if len(l) > 0]
    return labels

    
def parse_pcap(pcap_in, labels_in=None, verbose=False, max_num_packets=None, packet_lookup=None):
    """
    Parse and yield IPV4 headers from a given pcapng file.
    Also return the timestamp associated with the packet found
    via the EnhancedPacket object.

    Labels_in is a csv file. The csv file has column names "" and "x".
    "x" contains a 1 if a packet is malicious and a 0 otherwise

    Args:
      pcap_in: location of .pcap file to process
      labels_in: location of label file to process (if None assumes benign traffic)
      verbose: whether or not to notify about non-ipv4 packets
      max_num_packets: number of packets to parse
      packet_queue: If this generator is being used downstream to rewrite malicious
        traffic, it should place processed packets in the packet_queue. The packet
        queue is a heap ordered by packet sequence number. Items from the packet queue
        are consumed downstream by the packet modifier
    """

    labels = get_labels(labels_in) if labels_in is not None else None
    cur_packet = 0
    
    num_packets_parsed = 0
    with open(pcap_in, "rb") as fin:
        scanner = FileScanner(fin)
        for block in scanner:
            if type(block) == blocks.EnhancedPacket:
                try:
                    high_timestamp = block.timestamp_high
                    low_timestamp = block.timestamp_low
                    timestamp = (high_timestamp << 32) + low_timestamp
                    block_label = labels[cur_packet] if labels is not None else 0 # assume benign traffic
                    ip_header = IPv4Header.from_packet(block.packet_data)
                    if packet_lookup is not None:
                        packet_lookup[num_packets_parsed] = (ip_header,
                                                             block.packet_data,
                                                             block_label,
                                                             high_timestamp,
                                                             low_timestamp)
                    yield (ip_header, timestamp, block_label, num_packets_parsed)
                    num_packets_parsed += 1
                except IPFormatError as e:
                    if verbose:
                        print(e)
                cur_packet += 1
                if max_num_packets is not None and cur_packet >= max_num_packets:
                    break
    print("Done parsing {:s}. {:d} packets encountered. {:d} packets parsed. Label size {:d}".format(
        pcap_in, cur_packet, num_packets_parsed, len(labels) if labels is not None else -1))

                    
if __name__=="__main__":
    parser = argparse.ArgumentParser("Parse pcapng files for whisper")
    parser.add_argument("pcapng_file", type=str,
                        help="Location of the pcapng file.")
    args = parser.parse_args(sys.argv[1:])
    pcap_gen = parse_pcap(args.pcapng_file)

    for p in pcap_gen:
        pass




