"""
Splits a directory of pcap files into training and testing sets.
This module splits a traffic file after some percentage of its packets
to produce a training set and a testing set for a custom clustering
approach.
"""

import sys, os
import shutil
import argparse
import copy
import random
from multiprocessing import Pool

import numpy as np

from pcapng import FileScanner
from pcapng import FileWriter
from pcapng import blocks

import whisper_parser



def write_labels(labels, output_loc):
    """Writes the given labels to the given output location"""
    with open(output_loc, "w") as fout:
        fout.write("\n".join([str(l) for l in labels]))


def split_src_dest_pairs(raw_dataset_loc,
                         train_dataset_loc,
                         test_dataset_loc,
                         train_split_prob=0.2):
    """
    Splits the given raw dataset + labels into a training and testing set.
    Ensures any packets from the same sender and reciever are sent to the same
    partition.

    Args:
      raw_dataset_loc: Location of a raw dataset directory (containing a pcap file
        and labels)
      train_dataset_loc: Location of a directory where the training output should be
        placed.
      test_dataset_loc: Location of a directory where the testing output should be placed.
    """
    dataset_basename = os.path.basename(raw_dataset_loc)
    label_file_name = os.path.join(raw_dataset_loc, dataset_basename + "_labels.csv")
    if not os.path.exists(label_file_name):
        print("Could not find labels for {:s} at {:s}".format(dataset_basename, label_file_name))
        return
    pcapng_name = os.path.join(raw_dataset_loc, dataset_basename + "_pcap.pcapng")
    pcap_name = os.path.join(raw_dataset_loc, dataset_basename + "_pcap.pcap")    
    final_pcap_name = ""
    if os.path.exists(pcapng_name):
        final_pcap_name = pcapng_name
    elif os.path.exists(pcap_name):
        final_pcap_name = pcap_name
    else:
        print("Could not find pcap file for {:s} at {:s} or {:s}".format(
            dataset_basename, pcap_name, pcapng_name))
        return

    labels = whisper_parser.get_labels(label_file_name)
    
    cur_shb = None
    train_shb = None
    test_shb = None

    cur_writer = None
    train_out_stream = open(os.path.join(train_dataset_loc, dataset_basename + "_pcap.pcapng"), "wb")
    test_out_stream = open(os.path.join(test_dataset_loc, dataset_basename + "_pcap.pcapng"), "wb")    

    train_writer = None
    test_writer = None

    cul_label_list = None
    train_label_list = []
    test_label_list = []
    
    num_packets = 0
    assignments = {}
    
    with open(final_pcap_name, "rb") as fin:
        scanner = FileScanner(fin)
        for block in scanner:
            if type(block) == blocks.SectionHeader:
                train_shb = blocks.SectionHeader() # Might have to add back options
                test_shb = blocks.SectionHeader() # Might have to add back options
                cur_shb = train_shb
            if type(block) == blocks.InterfaceDescription:
                if train_shb is None and test_shb is None:
                    raise ValueError("No header block in {:s}".format(final_pcap_name))
                train_idb = train_shb.new_member(blocks.InterfaceDescription, link_type=1)
                test_idb = test_shb.new_member(blocks.InterfaceDescription, link_type=1)
                train_writer = FileWriter(train_out_stream, train_shb)
                test_writer = FileWriter(test_out_stream, test_shb)                
            elif type(block) == blocks.EnhancedPacket:
                if train_shb is None and test_shb is None:
                    raise ValueError("No header block in {:s}".format(final_pcap_name))
                packet_label = labels[num_packets]
                num_packets += 1
                try:
                    ip_header = whisper_parser.IPv4Header.from_packet(block.packet_data)
                    packet_key = (ip_header.src_addr, ip_header.dest_addr)
                    if packet_key not in assignments:
                        assignments[packet_key] = np.random.choice(
                            ["train", "test"], p=[train_split_prob, 1 - train_split_prob])
                    is_train = assignments[packet_key] == "train"
                    cur_shb = train_shb if is_train else test_shb
                    epb = cur_shb.new_member(blocks.EnhancedPacket)
                    epb.packet_data = copy.deepcopy(block.packet_data)
                    cur_writer = train_writer if is_train else test_writer
                    cur_writer.write_block(epb)
                    cur_label_list = train_label_list if is_train else test_label_list
                    cur_label_list.append(packet_label)
                except whisper_parser.IPFormatError:
                    continue

    write_labels(train_label_list, os.path.join(train_dataset_loc, dataset_basename + "_labels.csv"))
    write_labels(test_label_list, os.path.join(test_dataset_loc, dataset_basename + "_labels.csv"))
    train_out_stream.close()
    test_out_stream.close()


def split_temporally(raw_dataset_loc,
                     train_dataset_loc,
                     test_dataset_loc,
                     train_split_prob=0.2):
    """
    Splits the given raw dataset + labels into a training and testing set.
    The first train_split_prob * # packets are sent to the training set.
    The next (1 - train_split_prob) * # packets are sent to the testing set. 

    Args:
      raw_dataset_loc: Location of a raw dataset directory (containing a pcap file
        and labels)
      train_dataset_loc: Location of a directory where the training output should be
        placed.
      test_dataset_loc: Location of a directory where the testing output should be placed.
    """
    dataset_basename = os.path.basename(raw_dataset_loc)
    label_file_name = os.path.join(raw_dataset_loc, dataset_basename + "_labels.csv")
    if not os.path.exists(label_file_name):
        print("Could not find labels for {:s} at {:s}".format(dataset_basename, label_file_name))
        return
    pcapng_name = os.path.join(raw_dataset_loc, dataset_basename + "_pcap.pcapng")
    pcap_name = os.path.join(raw_dataset_loc, dataset_basename + "_pcap.pcap")    
    final_pcap_name = ""
    if os.path.exists(pcapng_name):
        final_pcap_name = pcapng_name
    elif os.path.exists(pcap_name):
        final_pcap_name = pcap_name
    else:
        print("Could not find pcap file for {:s} at {:s} or {:s}".format(
            dataset_basename, pcap_name, pcapng_name))
        return

    labels = whisper_parser.get_labels(label_file_name)
    
    cur_shb = None
    train_shb = None
    test_shb = None

    cur_writer = None
    train_out_stream = open(os.path.join(train_dataset_loc, dataset_basename + "_pcap.pcapng"), "wb")
    test_out_stream = open(os.path.join(test_dataset_loc, dataset_basename + "_pcap.pcapng"), "wb")    

    train_writer = None
    test_writer = None

    cul_label_list = None
    train_label_list = []
    test_label_list = []
    
    num_packets = 0
    
    with open(final_pcap_name, "rb") as fin:
        scanner = FileScanner(fin)
        for block in scanner:
            if type(block) == blocks.SectionHeader:
                train_shb = blocks.SectionHeader() # Might have to add back options
                test_shb = blocks.SectionHeader() # Might have to add back options
                cur_shb = train_shb
            if type(block) == blocks.InterfaceDescription:
                if train_shb is None and test_shb is None:
                    raise ValueError("No header block in {:s}".format(final_pcap_name))
                train_idb = train_shb.new_member(blocks.InterfaceDescription, link_type=1)
                test_idb = test_shb.new_member(blocks.InterfaceDescription, link_type=1)
                train_writer = FileWriter(train_out_stream, train_shb)
                test_writer = FileWriter(test_out_stream, test_shb)                
            elif type(block) == blocks.EnhancedPacket:
                if train_shb is None and test_shb is None:
                    raise ValueError("No header block in {:s}".format(final_pcap_name))
                is_train = num_packets < (train_split_prob * len(labels))
                packet_label = labels[num_packets]
                num_packets += 1
                try:
                    cur_shb = train_shb if is_train else test_shb
                    epb = cur_shb.new_member(blocks.EnhancedPacket)
                    epb.packet_data = copy.deepcopy(block.packet_data)
                    cur_writer = train_writer if is_train else test_writer
                    cur_writer.write_block(epb)
                    cur_label_list = train_label_list if is_train else test_label_list
                    cur_label_list.append(packet_label)
                except whisper_parser.IPFormatError:
                    continue

    write_labels(train_label_list, os.path.join(train_dataset_loc, dataset_basename + "_labels.csv"))
    write_labels(test_label_list, os.path.join(test_dataset_loc, dataset_basename + "_labels.csv"))
    train_out_stream.close()
    test_out_stream.close()


def get_split_arguments(raw_datasets_loc, split_datasets_loc):
    datasets = os.listdir(raw_datasets_loc)
    arguments = []
    for dataset in datasets:
        dset_train_dir = os.path.join(split_datasets_loc, "train", dataset)
        dset_test_dir = os.path.join(split_datasets_loc, "test", dataset)
        os.makedirs(dset_train_dir)
        os.makedirs(dset_test_dir)
        arguments.append((os.path.join(raw_datasets_loc, dataset), dset_train_dir, dset_test_dir))
    return arguments


if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_datasets_loc", type=str,
                        help="Location of unsplit datasets.")
    parser.add_argument("split_datasets_loc", type=str,
                        help="Location to place the split datasets.")
    parser.add_argument("num_processes", type=int,
                        help="Num processes to use to split the datasets")

    args = parser.parse_args(sys.argv[1:])

    if os.path.exists(args.split_datasets_loc):
        shutil.rmtree(args.split_datasets_loc)
                
    arguments = get_split_arguments(args.raw_datasets_loc, args.split_datasets_loc)

    with Pool(args.num_processes) as p:
        p.starmap(split_temporally, arguments)
    
