"""
This model seeks to mimic the implementation of Whisper found in fu et al. 2021. 
"""
import sys, os
import argparse
import json
import pdb

import torch
import numpy as np
import pandas as pd
from pcapng import utils

from whisper_parser import parse_pcap


class WhisperModel(torch.nn.Module):

    PKT_PROTO = 0
    PKT_LEN = 1
    PKT_TIME = 2
    
    def __init__(self, cluster_file=None, n_fft=50, mean_win_test=100):
        super(WhisperModel, self).__init__()
        self.packet_weights = torch.tensor([10, 0.1, -15.68])
        self.n_fft = n_fft                     # W_seg from paper
        self.mean_win_test = mean_win_test     # W_win from paper

        if cluster_file is not None:
            with open(cluster_file, "r") as fin:
                json_clusters = json.load(fin)
                self.centroids = torch.tensor(json_clusters)
        else:
            self.centroids = None

        
    def encode(self, packet_vectors):
        """
        Encode the given packet_vectors using
        a hard-coded encoding vector. 
        """
        log_time = torch.log2(packet_vectors[:,self.PKT_TIME:(self.PKT_TIME + 1)])
        log_transformed = torch.cat([
            packet_vectors[:,self.PKT_LEN:(self.PKT_LEN + 1)],
            packet_vectors[:,self.PKT_PROTO:(self.PKT_PROTO + 1)],
            log_time], axis=1)
        return torch.matmul(log_transformed, self.packet_weights)


    def get_flow_embeddings(self, packet_vectors):
        """
        Get embedding that is either used for clustering or used
        for inference (distance between embeddings)
        """
        encoded_packets = self.encode(packet_vectors) # N x 1
        complex_fft_packets = torch.stft(encoded_packets, self.n_fft)
        #real_fft_packets = torch.view_as_real(complex_fft_packets) # frames x frequencies x XY
        
        component_first = complex_fft_packets.permute(2, 0, 1)
        modulus = component_first[0] * component_first[0] + component_first[1] * component_first[1]
        modulus = modulus.squeeze()
        
        # log linear transform
        log_modulus = torch.log2(modulus + 1).permute(1, 0) # frequencies * frames
        zero_tensor = torch.full_like(log_modulus, 0)

        clean_log_modulus = torch.where(log_modulus.isnan(), zero_tensor, log_modulus)
        clean_log_modulus = torch.where(clean_log_modulus.isnan(), zero_tensor, clean_log_modulus)

        remaining_log_modulus = clean_log_modulus
        if clean_log_modulus.shape[0] < self.mean_win_test:
            raise ValueError("Not enough packets to run inference.")
        
        num_windows = clean_log_modulus.shape[0] // self.mean_win_test
        truncated_len =  num_windows * self.mean_win_test
        truncated_modulus = clean_log_modulus[:truncated_len]
        chunked_modulus = torch.reshape(truncated_modulus, (num_windows, -1) + truncated_modulus.shape[1:])
        chunked_means = chunked_modulus.mean(axis=0)
        return chunked_means

    
    def compute_distances(self, flow_embeddings):
        # We have one matrix that contains the observed points in a vector space. We have num_windows of
        #   such points. 
        # We have num_centroids centroids.
        # This finds a num_windows x num_centroids matrix of l2 distances between points and centroids
        interaction_term = -2 * torch.matmul(flow_embeddings, self.centroids.T)
        row_term = (flow_embeddings * flow_embeddings).sum(axis=1)
        col_term = (self.centroids * self.centroids).sum(axis=1)
        distances = torch.sqrt(row_term[:, None] + interaction_term + col_term[None, :])
        return distances


    
    def forward(self, packet_vectors):
        """
        A forward pass through Whisper

        Args:
          packet_vectors (torch.tensor) N x M array
            of features derived from traffic.
        """
        flow_embeddings = self.get_flow_embeddings(packet_vectors)
        distances = self.compute_distances(flow_embeddings)
        loss = distances.min(axis=1).values.max()
        return loss
    

# Dictionary from a (protocol, protocol type) tuple to
# an integer that is used to represent the feature
PROTO_VALS = {
    ("tcp", "syn"): 1,
    ("tcp", "fin"): 40,
    ("tcp", "rst"): 1,
    ("tcp", "ack"): 1000,
    ("tcp", None): 1000,
    ("udp", None): 3,
    ("icmp", None): 10,
    ("igmp", None): 9,
    ("unknown", None): 10
}

MIN_TIME_INTERVAL = 1e-5


def packet_window_to_numpy(packet_window):
    """
    Convert the given packet window (containes a list of
    header, timestamp tuples) to a N x M numpy matrix where
    N is the number of packets, and M is the number of features
    (length, . 
    """
    encoded_packets = []
    labels = []
    sequence_nums = []
    for i in range(len(packet_window)):
        cur_header, cur_timestamp, cur_label, sequence_num = packet_window[i]
        if i == 0:
            prev_timestamp = 1e9
        else:
            _, prev_timestamp, _, _ = packet_window[i - 1]
        delta_t = max(cur_timestamp - prev_timestamp, MIN_TIME_INTERVAL)
        encoded_packets.append([
            # ADD 3 elements
            PROTO_VALS[(cur_header.protocol, cur_header.protocol_type)], # protocol code
            cur_header.total_length,                                     # header length
            max(MIN_TIME_INTERVAL, cur_timestamp - prev_timestamp),      # timestamp
        ])
        labels.append(cur_label)
        sequence_nums.append(sequence_num)
    return (torch.tensor(encoded_packets, dtype=torch.float32),
            1 if any(labels) else 0,
            sequence_nums)




def get_packet_groups(header_gen, flow_window_size=1188, incomplete_groups=False): # 1188
    """
    Produce groups of packets from the given header
    generator. Yield sequences of packets of size
    `flow_window_size`

    Problem:
    - The flow window size of the authors is based on time
      not some number. I suspect higher window sizes are
      more accurate

    Args:
      header_gen (generator): Generator that yeilds
        ipv4 packet headers and timestamps.
      flow_window_size (int): Number of packets
        originating from a single source to use for
        analysis
    """
    sources = {} # (source ip -> list of packet headers & timestamps)

    for header, timestamp, label, sequence_num in header_gen:
        if header.src_addr not in sources:
            sources[header.src_addr] = []
        sources[header.src_addr].append((header, timestamp, label, sequence_num))
        if len(sources[header.src_addr]) == flow_window_size:
            first_timestamp = sources[header.src_addr][0][1]
            packet_matrix, matrix_label, sequence_nums = packet_window_to_numpy(
                sources[header.src_addr])
            yield (header.src_addr, first_timestamp, packet_matrix, matrix_label, sequence_nums)
            sources[header.src_addr] = []

    if not incomplete_groups:
        return

    # Incomplete windows (len < 1188)
    for source_ip, packet_window in sources.items():
        first_timestamp = packet_window[0][1]
        packet_matrix, matrix_label, sequence_nums = packet_window_to_numpy(packet_window)
        yield (source_ip, first_timestamp, packet_matrix, matrix_label, sequence_nums)
        



def run_inference(packet_matrix_gen, surogate_whisper):
    """
    Run the packets returned by packet_gen through the
    surogate model and record the results in a pandas dataframe
    """
    loss_and_labels = []
    for (src_addr, first_timestamp,
         packet_matrix, matrix_label, sequence_nums) in packet_matrix_gen:
        result = surogate_whisper.forward(packet_matrix)
        label_str = "MALICIOUS" if matrix_label == 1 else "BENIGN"
        print("{:15s}; {:5.5f}; {:s}".format(
            utils.unpack_ipv4(src_addr), float(result), label_str))
        loss_and_labels.append((float(result), matrix_label))

    loss_df = pd.DataFrame(loss_and_labels, columns=["loss", "label"])
    return loss_df


def write_results(result_df, output_file):
    output_dirname = os.path.dirname(output_file)
    if not os.path.exists(output_dirname):
        os.makedirs(output_dirname)
    result_df.to_csv(output_file, index=False)

    
if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcapng_file", type=str,
                        help="Location of the pcapng file.")
    parser.add_argument("centroid_file", type=str,
                        help="Location of the file containing learned centroids.")
    parser.add_argument("label_file", type=str,
                        help="Location of the file containing traffic labels.")
    parser.add_argument("results_file", type=str,
                        help="Location to put the resulting csv file.")
    args = parser.parse_args(sys.argv[1:])

    header_gen = parse_pcap(args.pcapng_file, args.label_file)
    packet_matrix_gen = get_packet_groups(header_gen)
    surogate_whisper = WhisperModel(cluster_file=args.centroid_file)

    result_df = run_inference(packet_matrix_gen, surogate_whisper)
    write_results(result_df, args.results_file)

    
        
