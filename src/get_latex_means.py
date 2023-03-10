"""
Finds the mean distance to centroids by attack type
and by whether a flow window is malicious or benign
"""

import sys, os
import argparse
import pandas as pd

import plot_roc

def find_means(results_loc, print_tex):
    columns = ["Attack Name", "Benign Distance", "Malicious Distance"]
    pretty_means = []
    for result_file in os.listdir(results_loc):
        if not result_file in plot_roc.pretty_names:
            print("Could not find pretty name for {:s}.".format(
                result_file))
            continue
        pretty_name = plot_roc.pretty_names[result_file]
        result_df = pd.read_csv(os.path.join(results_loc, result_file))
        mean_distances = result_df.groupby("label").agg(
            MEAN_DIST=("loss", "mean"))
        pretty_means.append(
            (pretty_name,
             mean_distances.loc[0, "MEAN_DIST"],
             mean_distances.loc[1, "MEAN_DIST"]))
    final_df = pd.DataFrame(pretty_means, columns=columns)
    if print_tex:
        print(final_df.to_latex(index=False,
                                float_format="{:2.2f}".format))
        print()
    print(final_df)

        


if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("results_loc", type=str,
                        help="Location of dataframes containing centroid distances")
    parser.add_argument("--print_tex", "-t", action="store_true",
                        help="Print out latex code for table")
    args = parser.parse_args(sys.argv[1:])

    if not os.path.exists(args.results_loc):
        print("Could not find file {:s}.".format(args.results_loc))
        exit()
        
    if not os.path.isdir(args.results_loc):
        print("{:s} is not a directory.".format(args.results_loc))
        exit()

    find_means(args.results_loc, args.print_tex)
        
    

