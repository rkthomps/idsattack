# idsattack
Packet modification to fool machine learning based network Intrusion Detection Systems (IDSs).

## System Overview
The goal of our system is to modify malicious traffic to make it appear benign to a target Intrusion Detection System (IDS). 
However, the important constraint in our project is that our modifications to traffic must not affect their functionality downstream!

![System Model](figures/system_model.drawio.png)

## Results
By adding nop options to IPv4 packet headers in a way that is specifically targeted at the IDS [Whisper](https://github.com/fuchuanpu/Whisper), we see the following changes in AUC on Whisper's testing set. 

| Attack Type         | Clean Traffic AUC   | Modified Traffic AUC  |
| ------------------- | ------------------- | --------------------- |
| SSL Renegotiation   |             0.72    |               0.53    |
| Fuzzing             |             0.61    |               0.45    |
| Syn DoS             |             0.56    |               0.33    |
| Video Injection     |             0.52    |               0.31    |
| ARP MITM            |             0.51    |               0.30    |
| Active Wiretap      |             0.51    |               0.31    |
| OS Scan             |             0.04    |               0.04    |
| SSDP Flood          |           < 0.01    |             < 0.01    |

## Datasets
We evaluate our system on datasets from [Kitsune](https://github.com/ymirsky/Kitsune-py). 
The datasets can be found in the [UC Irvine Machine Learning Repository](https://archive.ics.uci.edu/ml/machine-learning-databases/00516).

The script `download_datasets.py` will download the datasets from the repository. 
Alternatively, you can use these links to download archives containing the datasets:
- [Archive with all datasets](https://drive.google.com/file/d/10uN4b4vnvONGEzB54QBfb5V6X39eg571/view?usp=share_link)
- [Archive with training set](https://drive.google.com/file/d/1ephZY35lOUj3i7bzATCmcxgBIymjseEi/view?usp=share_link)
- [Archive with testing set](https://drive.google.com/file/d/10NBdq8gkAdT-7husfMtoorir0hzw9MJm/view?usp=share_link)
- [Archive with disguised testing set](https://drive.google.com/file/d/172IttXzyIResigHv98g1kkEb3BFqZvj-/view?usp=share_link)


## Reproducing Results
### Setting up Environment
