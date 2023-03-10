"""
Plots the roc curve of Whisper at all thresholds (between the minimum
and maximum observed cluster distances). 
"""

import sys, os
import argparse

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


pretty_names = {
    "active_wiretap": "Active Wiretap",
    "mirai": "Mirai",
    "ssdp_flood": "SSDP Flood",
    "syn_dos": "Syn DOS",
    "arp_mitm": "ARP MITM",
    "fuzzing": "Fuzzing",
    "os_scan": "OS Scan",
    "ssl_renegotiation": "SSL Renegotiation",
    "video_injection": "Video Injection"
}

pretty_name_keys = list(pretty_names.keys())
for key in pretty_name_keys:
    pretty_names[key + "-disguised"] = "DISGUISED " + pretty_names[key]


def compute_rates(loss_label_df, threshold):
    """
    Compute true positive and false positive rates of the dataframe
    of losses and labels using the given detection threshold
    (min distance to a centroid)
    """
    predicted = loss_label_df["loss"].values > threshold # 1 if malicious 0 if benign
    actual = loss_label_df["label"].values

    n_count = (1 - actual).sum()
    p_count = actual.sum()

    if n_count == 0 or p_count == 0:
        raise ValueError("Cannot plot ROC curve. Only 1 distinct target value.")

    fp_count = (predicted * (1 - actual)).sum()
    tp_count = (predicted * actual).sum()
    #print("Threshold: {:3.3f}, TPs {:3d}, FPs {:3d}, Ps {:3d}, Ns {:3d}".format(threshold, tp_count, fp_count, p_count, n_count))
    return fp_count / n_count, tp_count / p_count


def get_fpr_tpr_data(result_file_loc, roc_granularity=1000):
    result_df = pd.read_csv(result_file_loc)
    min_distance = result_df["loss"].min()
    max_distance = result_df["loss"].max()
    thresholds = np.linspace(min_distance, max_distance, roc_granularity)

    rates = []
    prev_fpr = -1
    for threshold in thresholds:
        fpr, tpr = compute_rates(result_df, threshold)
        if fpr == prev_fpr:
            continue
        else:
            prev_fpr = fpr
        rates.append((fpr, tpr))

    sorted_rates = sorted(rates, key=lambda x: x[0]) # sort by fpr
    sorted_fprs = [fpr for fpr, tpr in sorted_rates]
    sorted_tprs = [tpr for fpr, tpr in sorted_rates]
    return sorted_fprs, sorted_tprs


def plot_single_roc(result_file_loc, plot_save_loc, plot_title, roc_granularity=1000):
    sorted_fprs, sorted_tprs = get_fpr_tpr_data(result_file_loc,
                                                roc_granularity=roc_granularity)
    
    file_basename = os.path.basename(result_file_loc).replace(".csv", "")
    pretty_name = file_basename
    if file_basename in pretty_names:
        pretty_name = pretty_names[file_basename]
    
    fig, ax = plt.subplots()
    ax.plot(sorted_fprs, sorted_tprs)

    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(plot_title)
    
    fig.savefig(plot_save_loc)


def plot_multiple_roc(result_directory_loc, plot_save_loc, plot_title, roc_granularity=1000):
    fig, ax = plt.subplots()
    for result_file in os.listdir(result_directory_loc):
        file_basename = result_file.replace(".csv", "")
        if file_basename not in pretty_names:
            print("Results file {:s} not recognized.".format(result_file))
            continue
        pretty_name = pretty_names[file_basename]
        try:
            sorted_fprs, sorted_tprs = get_fpr_tpr_data(os.path.join(result_directory_loc, result_file),
                                                        roc_granularity=roc_granularity)
        except ValueError:
            print("{:s} results only has one target class.".format(pretty_name))
            continue
        
        ax.plot(sorted_fprs, sorted_tprs, label=pretty_name)

    ax.plot([0, 1], [0, 1], "k--", label="Random Guesser", alpha=0.5) 

    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(plot_title)
    fig.legend(loc="lower right")
    fig.savefig(plot_save_loc)



if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("results_loc", type=str,
                        help="Location of the two-column results file from running surogate whisper. If this is a file, a single plot is created for the file. If it is a directory, a plot is crated for every file in the directory.")
    parser.add_argument("save_loc", type=str,
                        help="Where should the plot be saved?")
    parser.add_argument("plot_title", type=str,
                        help="What should the plot be named?")
    args = parser.parse_args(sys.argv[1:])

    if not os.path.exists(args.results_loc):
        print("{:s} does not exist.".format(args.results_loc))
        exit()

    if os.path.isdir(args.results_loc):
        plot_multiple_roc(args.results_loc, args.save_loc, args.plot_title)
    else:
        plot_single_roc(args.results_loc, args.save_loc, args.plot_title)

    
    
