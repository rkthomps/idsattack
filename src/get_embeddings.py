
"""
Computes embeddings of benign traffic of all the datasets
in a given directory.

THIS REUSES THE GET_DETECTION_ARGUMENTS FUNCTION FROM RUN_DETECTION
"""

import sys, os
import shutil
import json
import argparse
from multiprocessing import Pool

import numpy as np
import torch

import run_detection
import whisper_model
import whisper_parser


def gather_embeddings(pcap_loc, label_loc, clusters_loc, result_loc):
    """
    Args:
      pcap_loc: path of pcap file that contains traffic to replay.
      label_loc: path of label file which determines if traffic is malicious
        or benign
      cluster_loc: only here for compatability with get_detection arguments
      result_loc describes where to save the results of running inference
    """
    surogate_model = whisper_model.WhisperModel()
    header_gen = whisper_parser.parse_pcap(pcap_loc, label_loc, max_num_packets=22547080)
    packet_matrix_gen = whisper_model.get_packet_groups(header_gen)

    embedding_list = []
    for (src_addr, first_timestamp,
         packet_matrix, matrix_label, sequence_nums) in packet_matrix_gen:
        if matrix_label == 1:
            continue
        result = surogate_model.get_flow_embeddings(packet_matrix)
        embedding_list.append(result)

    all_embeddings = torch.cat(embedding_list, axis=0)
    np.savez_compressed(result_loc, embeddings=all_embeddings.numpy())


if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("train_dataset_loc", type=str,
                        help="Path to training datasets containing pcap/pcapng files and labels")
    parser.add_argument("results_loc", type=str,
                        help="Path to directory where to store the resulting embeddings.")
    parser.add_argument("num_processes", type=int,
                        help="Number of processes to use to run detection")
    args = parser.parse_args(sys.argv[1:])
    if os.path.exists(args.results_loc):
        shutil.rmtree(args.results_loc)
    os.makedirs(args.results_loc)

    process_arguments = run_detection.get_detection_arguments(
        args.train_dataset_loc, "fakeclusters", args.results_loc)

    with Pool(args.num_processes) as p:
        p.starmap(gather_embeddings, process_arguments)
    







