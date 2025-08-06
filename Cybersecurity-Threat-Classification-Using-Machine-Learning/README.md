# Cybersecurity Threat Classification Using Machine Learning

# Project Description
With the rise in cyber threats such as malware, phishing, and DDoS attacks, securing network infrastructure is a top priority. This project utilizes Machine Learning (ML) to classify network traffic as normal or malicious, using the CIC-IDS-2017 dataset. By employing models like Random Forest and Neural Networks, we aim to build an efficient threat detection system that enhances cybersecurity.

# Dataset

We use the CIC-IDS-2017 dataset, which contains labeled network traffic data representing real-world attacks and normal behavior. It is available for download from here.

# Installation

Prerequisites
Ensure you have the following installed:
Python 3.x
Jupyter Notebook or Google Colab
Required Python libraries

# Usage

Load and Preprocess Data
Read the CIC-IDS-2017 dataset.

Handle missing values and scale features.

Train Machine Learning Models

1) Random Forest Classifier
2) Neural Network (MLPClassifier)

Evaluate Performance
Accuracy, Precision, Recall, and F1-score.

Confusion Matrix for better insights.

Run the # Cybersecurity Threat Classification Using Machine Learning.ipynb notebook to execute these steps.

# Results & Visualization

We visualize the performance using:
✔ Confusion Matrix – Shows the model’s misclassification.
✔ Feature Importance – Highlights key features used in classification.

# Future Improvements

✔ Integrate real-time threat detection
✔ Implement Federated Learning for enhanced privacy
✔ Deploy the model using Flask/FastAPI
