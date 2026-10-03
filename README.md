# 🔐 Cybersecurity Log Monitoring & Anomaly Detection System

A cybersecurity web application that monitors employee activity, records application-level security logs, and uses **Isolation Forest** to detect unusual user behavior.

## 📖 Overview

The system combines an **Organization Employee Portal** with a backend security monitoring system. Employee activities such as login attempts, file access, downloads, profile actions, and password changes are automatically recorded and analyzed for anomalous behavior.

## ✨ Features

👤 Employee Login & Registration
📝 Automatic Security Activity Logging
📁 File Access & Download Monitoring
🔑 Login & Password Activity Monitoring
🧠 Isolation Forest-based Anomaly Detection
📊 Security Monitoring Dashboard
🚨 Anomaly Scores & Security Alerts
🌐 IP Address & Timestamp Tracking

## 🏗️ Project Architecture

```text
Employee Portal
      │
      ▼
Flask Backend
      │
      ▼
MySQL Security Logs
      │
      ▼
Feature Extraction
      │
      ▼
Isolation Forest
      │
      ▼
Normal / Anomaly
      │
      ▼
Security Dashboard
```

## 🧠 Model Details

**Model:** Isolation Forest
**Type:** Unsupervised Anomaly Detection
**Features:** Failed logins, total events, file activity, profile activity, password changes, and unique IPs.

## 🛠️ Tech Stack

**Machine Learning:** Python, Scikit-learn, Isolation Forest
**Backend:** Flask, Python
**Database:** MySQL
**Frontend:** HTML, CSS, JavaScript
**Security:** Werkzeug Password Hashing, Session Authentication

## Images
<img width="206" height="277" alt="image" src="https://github.com/user-attachments/assets/19563a94-1662-4370-a960-12c47bf4b87a" /> 
<img width="666" height="228" alt="image" src="https://github.com/user-attachments/assets/f3118598-eeff-480b-914e-83e0b124a77c" />
<img width="230" height="195" alt="image" src="https://github.com/user-attachments/assets/dba26f4a-1c3a-4715-9fbf-cf868fa534d3" /> 
<img width="650" height="377" alt="image" src="https://github.com/user-attachments/assets/c57009bc-0da4-44c3-94f0-37f9dbabfae3" />
<img width="594" height="343" alt="image" src="https://github.com/user-attachments/assets/5f0c7967-b1e7-4076-9fac-46a60c3358ed" />








## 👩‍💻 Author

**Harshini Perumal**
B.E. Artificial Intelligence & Machine Learning
Nitte Meenakshi Institute of Technology, Bengaluru
