# Detecting and Defending Against IoT Intrusions Leveraging Data for Enhanced Security

## Project Overview

This project focuses on developing a robust machine learning-based framework to detect and defend against intrusion attempts in Internet of Things (IoT) environments. Using advanced data analysis and classification algorithms, the system leverages network traffic data to identify and classify malicious activities, enhancing the overall security of IoT infrastructures.

This work is being published in **Springer Nature SNAPP, Journal of Network and Systems Management**.

---

## 🔍 Objectives

- Analyze IoT network traffic using real-world intrusion datasets.
- Apply feature engineering to improve detection accuracy.
- Train multiple machine learning models (e.g., Random Forest, SVM, Neural Networks).
- Evaluate and compare models on classification performance metrics.
- Propose defensive mechanisms based on data insights.

---

## Dataset Used

**CICIDS2017 Dataset** – Provided by the Canadian Institute for Cybersecurity.  
It includes labeled attack traffic for various intrusion scenarios (DDoS, PortScan, Brute Force, etc.).

Dataset link: https://www.unb.ca/cic/datasets/ids-2017.html

---

## Running the Project

1. **Preprocess and Train Models**
```bash
Detecting and Defending Against IoT Intrusions Leveraging Data for Enhanced Security.ipynb
```

2. **Notebook for Analysis**
Open JupyterLab or VSCode for step-by-step execution.

---

## Evaluation Metrics

Models are evaluated using the following:
- Accuracy
- Precision, Recall, F1-score
- Feature Importance Visualization

---

## Key Findings

- Random Forest provided the highest accuracy (~99%) in intrusion classification.
- Top contributing features included `Flow Duration`, `Dst Port`, `Packet Length`, and `Flow Bytes/s`.
- Feature selection significantly improved both performance and model generalization.

---

## 💡 Future Enhancements

- Incorporate Deep Learning architectures (LSTM, CNNs).
- Integrate real-time detection using stream-processing frameworks.
- Extend the framework for federated learning on edge IoT devices.

---
