
"""
Fit the generic sklearn clustering algorithm to the training data embeddings. 
"""
import sys, os
import argparse
import numpy as np
from sklearn.cluster import KMeans
import json

def get_centroids(num_clusters, embedding_directory, save_loc):
    """
    Concatenates all of the training embeddings together
    and finds the centroids of 10 clusters using the K-Means
    Clustering algorithm.
    """
    embedding_list = []
    for npz_file in os.listdir(embedding_directory):
        embeddings = np.load(os.path.join(embedding_directory, npz_file))["embeddings"]
        embedding_list.append(embeddings)
    all_embeddings = np.concatenate(embedding_list, axis=0)
    clusterer = KMeans(n_clusters=num_clusters, n_init="auto")
    clusterer.fit(all_embeddings)
    centroids = clusterer.cluster_centers_
    centroids_as_lists = [[float(el) for el in row] for row in centroids]
    save_dirname = os.path.dirname(save_loc)
    if not os.path.exists(save_dirname):
        os.makedirs(save_dirname)
    
    with open(save_loc, "w") as fout:
        fout.write(json.dumps(centroids_as_lists))
    

def get_centroids_per_file(num_clusters, embedding_directory, save_loc):
    """
    Finds num_clusters centroids per attack type in embedding directory
    """
    if os.path.exists(save_loc):
        shutil.rmtree(save_loc)
    os.makedirs(save_loc)
    for embedding_matrix_name in os.listdir(embedding_directory):
        attack_name = embedding_matrix_name.replace(".npz", "")
        embeddings = np.load(os.path.join(embedding_directory, embedding_matrix_name))["embeddings"]
        clusterer = KMeans(n_clusters=num_clusters, n_init="auto")
        clusterer.fit(embeddings)
        centroids = clusterer.cluster_centers_
        centroids_as_lists = [[float(el) for el in row] for row in centroids]
        save_path = os.path.join(save_loc, attack_name) + "_centroids.json"
        with open(save_path, "w") as fout:
            fout.write(json.dumps(centroids_as_lists))
        


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("embedding_dir_loc", type=str,
                        help="Location of the benign traffic flow embeddings.")
    parser.add_argument("num_clusters", type=int,
                        help="Number of clusters.")
    parser.add_argument("save_loc", type=str,
                        help="Which file to which to save the centroids.")
    args = parser.parse_args(sys.argv[1:])
    #get_centroids(args.num_clusters, args.embedding_dir_loc, args.save_loc)
    get_centroids_per_file(args.num_clusters, args.embedding_dir_loc, args.save_loc)

