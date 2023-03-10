
"""
Runs detection at mass. Produces results for all
datasets found in a given directory. 
"""

import sys, os
import shutil
import json
import argparse
from multiprocessing import Pool

import whisper_model
import whisper_parser


def get_detection_arguments(datasets_loc, clusters_loc, results_loc):
    """
    Returns a list of tuples where each tuple contains arguments
    to a call of run_detection. The tuples can therefore be run
    in parallel.
    
    Args:
      datasets_loc: path to directory containing pcap files and labels
      clusters_loc: path to a json file containing a n x 26 matrix
        of centroids
      results_loc: where to save the detection results
    """
    datasets = os.listdir(datasets_loc)
    arguments = []
    for dataset in datasets:
        dset_results_loc = os.path.join(results_loc, dataset)
        label_file_name = os.path.join(datasets_loc, dataset, dataset + "_labels.csv")
        if not os.path.exists(label_file_name):
            print("Could not find labels for {:s} at {:s}. Assuming Benign Traffic".format(
                dataset, label_file_name))
            label_file_name = None
        pcapng_name = os.path.join(datasets_loc, dataset, dataset + "_pcap.pcapng")
        pcap_name = os.path.join(datasets_loc, dataset, dataset + "_pcap.pcap")
        final_pcap_name = ""
        if os.path.exists(pcapng_name):
            final_pcap_name = pcapng_name
        elif os.path.exists(pcap_name):
            final_pcap_name = pcap_name
        else:
            print("Could not find pcap file for {:s} at {:s} or {:s}".format(
                dataset, pcap_name, pcapng_name))
            continue
        attack_cluster_loc = clusters_loc
        if os.path.isdir(clusters_loc):
            attack_cluster_loc = os.path.join(clusters_loc, dataset) + "_centroids.json"
            if not os.path.exists(attack_cluster_loc):
                print("Could not find clusters for {:s} at {:s}".format(dataset, attack_cluster_loc))
                continue
        arguments.append((final_pcap_name, label_file_name, attack_cluster_loc, dset_results_loc))
    return arguments


def run_detection(pcap_loc, label_loc, clusters_loc, result_loc):
    """
    Args:
      pcap_loc: path of pcap file that contains traffic to replay.
      label_loc: path of label file which determines if traffic is malicious
        or benign
      cluster_loc: location of centroids to use for detection
      result_loc describes where to save the results of running inference
    """
    surogate_model = whisper_model.WhisperModel(clusters_loc)
    header_gen = whisper_parser.parse_pcap(pcap_loc, label_loc)
    packet_matrix_gen = whisper_model.get_packet_groups(header_gen)
    
    result_df = whisper_model.run_inference(packet_matrix_gen, surogate_model)
    whisper_model.write_results(result_df, result_loc)


if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("datasets_loc", type=str,
                        help="Path to datasets containing pcap/pcapng files and labels")
    parser.add_argument("clusters_loc", type=str,
                        help="Location of json file containing cluster centroids")
    parser.add_argument("results_loc", type=str,
                        help="Path to directory where to store detection results")
    parser.add_argument("num_processes", type=int,
                        help="Number of processes to use to run detection")
    args = parser.parse_args(sys.argv[1:])
    if os.path.exists(args.results_loc):
        shutil.rmtree(args.results_loc)
        os.makedirs(args.results_loc)

    process_arguments = get_detection_arguments(args.datasets_loc, args.clusters_loc, args.results_loc)

    with Pool(args.num_processes) as p:
        p.starmap(run_detection, process_arguments)
    







