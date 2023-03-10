
"""
This disguises malicious packets to appear benign.
"""

import sys, os
import argparse
import shutil

import numpy as np
import torch

import whisper_parser
import whisper_model
from whisper_parser import IPv4Header as IP4

from run_detection import get_detection_arguments

from pcapng import FileWriter, blocks

import pdb

from multiprocessing import Pool


def define_packet_options(sequence_nums, packet_lookup,
                          max_packet_length=144, min_header_length=5, max_header_length=15):
    """
    We will only add no-ops to packets that are not fragmented and could not
    be fragmented by the addition of no-ops. We assume MTU of 576 bytes (144 dwords).
    Headers must be between 5 and 15 dwords.
    
    Ipv4 packets cannot have a header with length less than 20 bytes or greater
    than 60 bytes.
    The Ipv4 header must be aligned to a 32-bit boundary. That means we can only
    increase/decrease its size by 4 bytes at a time.

    Packet Options is a datastructure that has all of the possible changes to a packet
    header.
    Curselection is the index of the identity selection (0) in each list of packet options
    
    Ex
    [-2, -1, 0, 1]
    This means that one could change the packet header length by -2, -1, 0, or 1 quad
    words and the header is currently unchanged
    """
    flow_options = []
    cur_selections = []
    for seq_no in sequence_nums:
        packet_header, _, _, _, _ = packet_lookup[seq_no]
        if packet_header.is_fragment:
            flow_options.append([0])
            cur_selections.append(0)
            continue
            
        # Make Packet Smaller (not clear that we should actually do this)
        packet_options = []
        #decrease_options = list(range(5 - packet_header.header_length, 0))
        decrease_options = []
        packet_options.extend(decrease_options)

        # Identity Option
        packet_options.append(0)

        # Make Packet Larger
        wiggle_dwords = int(np.ceil(packet_header.total_length / 4) - max_packet_length)
        max_header_len = min(packet_header.header_length + wiggle_dwords, max_header_length)
        increase_options = list(range(1, max_header_len - packet_header.header_length))
        packet_options.extend(increase_options)
        flow_options.append(packet_options)
        cur_selections.append(len(decrease_options))
    return flow_options, cur_selections



def single_step_modify(packet_matrix, surogate_model, sequence_nums,
                       packet_lookup, modify_rounds=1):
    """
    Perform modify_rounds iterations. At each iteration, step through
    each packet and find the option that has the smallest loss. If there
    is a new smallest loss, update the packet matrix for all subsequent
    perturbations
    """
    flow_options, cur_selections = define_packet_options(sequence_nums, packet_lookup)
    numpy_packet_matrix = packet_matrix.numpy()
    original_packet_matrix = numpy_packet_matrix.copy()
    prev_numpy_matrix = original_packet_matrix
    best_options = cur_selections
    og_loss = float(surogate_model(torch.tensor(packet_matrix)))
    best_loss = og_loss
    for modify_round in range(modify_rounds):
        best_options = []
        for packet_num in range(len(cur_selections)):
            best_option = -1
            best_loss = 1e9
            option_numpy_matrix = numpy_packet_matrix.copy()
            original_val = original_packet_matrix[packet_num][surogate_model.PKT_LEN]            
            for i, option in enumerate(flow_options[packet_num]):
                option_numpy_matrix[packet_num][surogate_model.PKT_LEN] = original_val + 4 * option
                torch_packet_matrix = torch.tensor(option_numpy_matrix)
                option_loss = float(surogate_model(torch_packet_matrix))
                if option_loss < best_loss:
                    best_loss = option_loss
                    best_option = i
            best_options.append(best_option)
            best_increment = flow_options[packet_num][best_option]
            numpy_packet_matrix[packet_num][surogate_model.PKT_LEN] = original_val + 4 * best_increment
        if (numpy_packet_matrix == prev_numpy_matrix).all():
            break
        prev_numpy_packet_matrix = numpy_packet_matrix.copy()
    print("Loss {:5.5f} -> {:5.5f}".format(og_loss, best_loss))
    return flow_options, best_options
    

    

def simple_grad_modify(packet_matrix, surogate_model, sequence_nums,
                       packet_lookup, modify_rounds=10):
    """
    Create a new packet matrix by modifying the packet length by
    steps of 4 bytes.

    Following the gradients is bad: all the packet lengths pretty much
    have positive gradients.

    Lets do a random approach! If the gradient is nonzero, increment
    the cur_selection by one
    """
    min_loss = 1e9
    best_selections = []
    best_round = -1
    start_loss = None
    packet_matrix_floats = packet_matrix.numpy()
    flow_options, cur_selections = define_packet_options(sequence_nums, packet_lookup)
    for modify_round in range(modify_rounds):
        torch_packet_matrix = torch.tensor(packet_matrix_floats, requires_grad=True)
        loss = surogate_model(torch_packet_matrix)
        if start_loss is None:
            start_loss = loss
        if float(loss) < min_loss:
            min_loss = float(loss)
            best_selections = cur_selections.copy()
            best_round = modify_round
        loss.backward()
        input_grads = torch_packet_matrix.detach().numpy()
        perturbation = np.full_like(packet_matrix.numpy(), 0.0)

        for i in range(input_grads.shape[0]):
            pkt_len_grad = input_grads[i][surogate_model.PKT_LEN]
            if pkt_len_grad == 0:
                continue
            
            if pkt_len_grad > 0 and cur_selections[i] > 0:
                cur_selections[i] -= 1
                perturbation[i][surogate_model.PKT_LEN] -= 4
                continue

            if pkt_len_grad < 0 and cur_selections[i] < len(flow_options[i]) - 1:
                cur_selections[i] += 1
                perturbation[i][surogate_model.PKT_LEN] += 4
                continue
        packet_matrix_floats += perturbation
    print("Loss {:5.5f} -> {:5.5f}. Best round {:d}".format(start_loss, min_loss, best_round))
    return flow_options, best_selections


def make_modifications(flow_options, best_selections, sequence_nums, packet_lookup, write_queue):
    """
    For each of the modified sequence numbers, the function makes the discovered modification to
    the actual packet bytes and removes the packets from the packet_lookup table and adds them
    to the write queue. 
    """
    for i, seq_num in enumerate(sequence_nums):
        packet_header, packet_data, packet_label, high_timestamp, low_timestamp = packet_lookup[seq_num]
        num_nop_dwords = flow_options[i][best_selections[i]]

        # Modify IHL
        ihl_end = IP4.IHL_OFF + IP4.IHL_LEN
        ihl_byte = packet_data[IP4.IHL_OFF]
        version = ihl_byte & IP4.VERSION_MASK
        ihl = ihl_byte & IP4.IHL_MASK
        new_ihl = ihl + num_nop_dwords
        packet_data = packet_data[:IP4.IHL_OFF] + bytes([new_ihl + version]) + packet_data[ihl_end:]

        # Modify Total Len
        total_len_end = IP4.LENGTH_OFF + IP4.LENGTH_LEN
        total_len = int.from_bytes(
            packet_data[IP4.LENGTH_OFF:total_len_end], "big")
        total_len += 4 * num_nop_dwords
        len_bytes = int.to_bytes(total_len, 2, "big")
        packet_data = packet_data[:IP4.LENGTH_OFF] + len_bytes + packet_data[total_len_end:]

        # Add nop option packets
        nop_val = 0x01
        header_end = IP4.IP_HEAD_OFF+(ihl * 4)
        cur_packet_header = packet_data[:header_end]
        cur_packet_contents = packet_data[header_end:]
        nops = bytes([nop_val] * num_nop_dwords * 4)
        packet_data = cur_packet_header + nops + cur_packet_contents

        write_queue[seq_num] = packet_data, packet_label, high_timestamp, low_timestamp
        packet_lookup.pop(seq_num)


def add_benign_to_write_queue(sequence_nums, packet_lookup, write_queue):
    for seq_num in sequence_nums:
        packet_header, packet_data, packet_label, high_timestamp, low_timestamp = packet_lookup[seq_num]
        write_queue[seq_num] = packet_data, packet_label, high_timestamp, low_timestamp
        packet_lookup.pop(seq_num)


def write_packets_sequentially(shb, writer, label_list, write_queue, cur_seq_no):
    """
    Checks if the packet data associated with cur_seq_no exists
    in the write queue. if it does, write it to the Section Header Block
    and increment the seq no
    """
    while cur_seq_no in write_queue:
        epb = shb.new_member(blocks.EnhancedPacket)
        packet_data, packet_label, high_timestamp, low_timestamp = write_queue[cur_seq_no]
        epb.packet_data = packet_data
        epb.timestamp_low = low_timestamp
        epb.timestamp_high = high_timestamp
        writer.write_block(epb)
        write_queue.pop(cur_seq_no)
        label_list.append(packet_label)
        cur_seq_no += 1
    return cur_seq_no


def write_labels(labels, output_loc):
    """Writes the given labels to the given output location"""
    with open(output_loc, "w") as fout:
        fout.write("\n".join([str(l) for l in labels]))


def disguise_traffic(pcap_loc, label_loc, clusters_loc, result_loc):
    """
    Queries a surogate Whisper model to determine what modifications to make
    to each packet from the traffic at pcap_loc

    Args:
      pcap_loc: path to a pcapng file with traffic to modify
      label_loc: path to labels for packets found in the given pcapng file
      clusters_loc: path to a json file with centroids for malicious traffic detection
      new_pcap_loc: where to write the result of modifying traffic. 
    """
    packet_lookup = {}
    write_queue = {}
    label_list = []
    header_gen = whisper_parser.parse_pcap(pcap_loc, label_loc, packet_lookup=packet_lookup)
    packet_matrix_gen = whisper_model.get_packet_groups(header_gen, incomplete_groups=True)
    surogate_model = whisper_model.WhisperModel(clusters_loc)
    os.makedirs(result_loc)

    # Create pcapng writer
    label_basename = os.path.basename(label_loc)    
    pcap_basename = os.path.basename(pcap_loc)
    pcap_out_stream = open(os.path.join(result_loc, pcap_basename), "wb")

    shb = blocks.SectionHeader()
    idb = shb.new_member(blocks.InterfaceDescription, link_type=1)

    writer = FileWriter(pcap_out_stream, shb)
    cur_seq_no = 0
    for (src_addr, first_timestamp,
         packet_matrix, matrix_label, sequence_nums) in packet_matrix_gen:
        if matrix_label == 0 or packet_matrix.shape[0] < 1188:
            add_benign_to_write_queue(sequence_nums, packet_lookup, write_queue)
        else:
            flow_options, best_selections = single_step_modify(packet_matrix, surogate_model,
                                                               sequence_nums, packet_lookup)
            make_modifications(flow_options, best_selections, sequence_nums, packet_lookup, write_queue)
        cur_seq_no = write_packets_sequentially(shb, writer, label_list, write_queue, cur_seq_no)

    write_labels(label_list, os.path.join(result_loc, label_basename))

    assert len(packet_lookup) == 0
    assert len(write_queue) == 0
    pcap_out_stream.close()
        

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("datasets_loc", type=str,
                        help="Location of datasets (pcapng files and labels) containing malicious packets to disguise")
    parser.add_argument("centroid_loc", type=str,
                        help="Location of centroids to use to instantiate the Whisper model")
    parser.add_argument("results_loc", type=str,
                        help="Where to store the modified traffic")
    parser.add_argument("num_processes", type=int,
                        help="Number of processes to use to disguise the traffic.")
    args = parser.parse_args(sys.argv[1:])

    if os.path.exists(args.results_loc):
        shutil.rmtree(args.results_loc)

    disguise_arguments = get_detection_arguments(args.datasets_loc, args.centroid_loc, args.results_loc)
    with Pool(args.num_processes) as p:
        p.starmap(disguise_traffic, disguise_arguments)


        
    
    









