
"""
Downloads datasets from Irvine Machine Learning Repository.
"""

import sys, os
import argparse
import requests
import shutil
import gzip
import re


def download_datasets(download_dir):
    """
    Downloads datasets from UCI Machine Learning Repository
    https://archive.ics.uci.edu/ml/datasets/Kitsune+Network+Attack+Dataset#
    """
    total_prefix = "https://archive.ics.uci.edu/ml/machine-learning-databases/00516"

    if os.path.exists(download_dir):
        overwrite = input("Download dir exists. Overwrite?: ")
        if overwrite.startswith("y"):
            shutil.rmtree(download_dir)
        else:
            return

    os.makedirs(download_dir)
    print("Downloading description...", end=" ")
    desc_name = "description.txt"
    desc_url = total_prefix + "/" + desc_name
    request_result = requests.get(desc_url).content
    print("writing...")
    with open(os.path.join(download_dir, desc_name), "wb") as fout:
        fout.write(request_result)

    datasets = [
        ("Active%20Wiretap", "active_wiretap"),
        ("ARP%20MitM", "arp_mitm"),
        ("Fuzzing", "fuzzing"),
        ("Mirai", "mirai"),
        ("OS%20Scan", "os_scan"),
        ("SSDP%20Flood", "ssdp_flood"),
        ("SSL%20Renegotiation", "ssl_renegotiation"),
        ("SYN%20DoS", "syn_dos"),
        ("Video%20Injection", "video_injection")
    ]

    dataset_postfixs = ["_labels.csv.gz", "_pcap.pcapng.gz", "_pcap.pcap.gz"]
    suffix_remove = re.compile(r"\.gz$")
    
    print("Downloading into {:s}".format(download_dir))
    for url_name, read_name in datasets:
        os.makedirs(os.path.join(download_dir, read_name))
        for postfix in dataset_postfixs:
            url = total_prefix + "/" + read_name + "/" + url_name + postfix
            print("Downloading {:s}...".format(read_name + postfix), end=" ")
            sys.stdout.flush()
            request_result = requests.get(url).content
            try:
                decompressed_request_result = gzip.decompress(request_result)
            except gzip.BadGzipFile:
                print("aborting.")
                continue
            print("writing...")
            clean_postfix = suffix_remove.sub("", postfix)
            result_path = os.path.join(download_dir,
                                       read_name, read_name + clean_postfix) 
            with open(result_path, "wb") as fout:
                fout.write(decompressed_request_result)
            


if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("download_loc",
                        help="Top level download directory.")
    args = parser.parse_args(sys.argv[1:])
    
    download_datasets(args.download_loc)
