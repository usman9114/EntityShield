import os
import random

def load_training_data():
    """
    Load the phishing domains and benign domains from disk into python lists

    NOTE: I'm using a smaller set of samples than from the CLI tool so the feature extraction is quicker.

    @return training_data: dictionary where keys are domain names and values
                are labels (0 = benign, 1 = phishing).
    """
    training_data = {}

    benign_path = "training_data/benign/"
    for root, dirs, files in os.walk(benign_path):
        files = [f for f in files if not f[0] == "."]
        for f in files:
            with open(os.path.join(root, f)) as infile:
                for item in infile.readlines():
                    # Safeguard to prevent adding duplicate data to training set.
                    if item not in training_data:
                        training_data[item.strip('\n')] = 0

    phishing_path = "training_data/malicious/"
    for root, dirs, files in os.walk(phishing_path):
        files = [f for f in files if not f[0] == "."]
        for f in files:
            with open(os.path.join(root, f)) as infile:
                for item in infile.readlines():
                    # Safeguard to prevent adding duplicate data to training set.
                    if item not in training_data:
                        training_data[item.strip('\n')] = 1

    print("[+] Completed.")
    print("\t - Not phishing domains: {}".format(sum(x == 0 for x in training_data.values())))
    print("\t - Phishing domains: {}".format(sum(x == 1 for x in training_data.values())))
    return training_data

training_data = load_training_data()
# Compute features.
print("[*] Computing features...")
from phishing import PhishFeatures
f = PhishFeatures()
training_features = f.compute_features(training_data.keys(), values_only=False)
feature_vector = training_features['names']
print("[+] Features computed for the {} samples in the training set.".format(len(training_features['values'])))


from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import numpy as np

# Assign the labels (0s and 1s) to a numpy array.
labels = np.fromiter(training_data.values(), dtype=np.float)
print("[+] Assigned the labels to a numpy array.")

# Split the data into a training set and a test set.
X_train, X_test, y_train, y_test = train_test_split(training_features['values'], labels, random_state=5)
print("[+] Split the data into a training set and test set.")

# Insert silver bullet / black magic / david blaine / unicorn one-liner here :)
classifier = LogisticRegression(C=10).fit(X_train, y_train)
print("[+] Completed training the classifier: {}".format(classifier))
