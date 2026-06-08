# PhishShield: Detection of Phishing Links and Fake QR Codes for UPI Transactions

## Project Description

PhishShield is a cybersecurity-based web application that detects phishing URLs and fraudulent QR codes used in UPI payment scams. The system combines Machine Learning, Deep Learning, SSL certificate verification, IP address analysis, domain location analysis, and typosquatting detection to identify malicious websites and fake payment QR codes.

## Problem Statement

Cybercriminals increasingly use phishing websites and fake QR codes to steal sensitive user information and conduct financial fraud. Traditional blacklist-based approaches are unable to detect newly created phishing domains and sophisticated QR-based attacks. This project provides a multi-layered intelligent detection system for identifying phishing threats before users interact with them.

## Objectives

* Detect phishing URLs using machine learning.
* Detect fake QR codes using deep learning.
* Verify SSL certificates of websites.
* Analyze domain IP addresses and hosting locations.
* Detect typosquatting attacks on popular brands.
* Provide real-time security risk assessment.
* Improve protection against UPI-related fraud.

## Features

### URL Security Analysis

* URL feature extraction
* Phishing prediction
* Domain age analysis
* Suspicious keyword detection

### SSL Certificate Verification

* SSL availability check
* Certificate validity verification
* Certificate expiry monitoring

### IP Address Analysis

* IP lookup
* Reputation analysis
* Hosting provider information

### Domain Location Analysis

* Country identification
* Geolocation verification
* Risk assessment based on location

### Typosquatting Detection

* Brand similarity detection
* Levenshtein distance matching
* Detection of fake look-alike domains

### QR Code Security

* QR code decoding
* Fake QR code detection using EfficientNetB0
* UPI QR verification

## System Architecture

User Input (URL / QR Code)
│
▼
Data Collection Layer
│
┌──────────┼──────────┐
▼          ▼          ▼
SSL      IP Analysis  Location
Check                 Analysis
│
▼
Typosquatting Detection
│
▼
Machine Learning Engine
│
▼
Risk Assessment Module
│
▼
Safe / Suspicious / Phishing

## Technologies Used

### Programming Language

* Python

### Web Framework

* Django

### Machine Learning

* Scikit-learn
* TensorFlow
* Keras

### Computer Vision

* OpenCV
* Pyzbar

### Database

* SQLite

### Frontend

* HTML
* CSS
* JavaScript

### Other Libraries

* NumPy
* Pandas
* Requests
* Whois
* SSL
* Socket

## Project Structure

phishshield/

├── dataset/

├── models/

├── phishing_detection/

│   ├── url_features.py

│   ├── ssl_checker.py

│   ├── ip_analysis.py

│   ├── location_checker.py

│   ├── typosquatting.py

│   └── predict.py

├── qr_detection/

│   ├── qr_decoder.py

│   ├── qr_classifier.py

│   └── efficientnet_model.py

├── django_app/

├── docs/

├── requirements.txt

└── README.md

## Installation

1. Clone the repository

git clone https://github.com/yourusername/phishshield.git

2. Move into the project directory

cd phishshield

3. Install required packages

pip install -r requirements.txt

4. Run the Django server

python manage.py runserver

## Usage

1. Open the application.
2. Upload a QR code image or enter a URL.
3. The system performs security analysis.
4. Results are displayed with risk scores.
5. Users receive security recommendations.

## Research Gap

Existing phishing detection systems mainly focus on URL-based features and often ignore additional security indicators such as SSL certificates, IP reputation, geolocation information, typosquatting behavior, and QR-code-based attacks. This project addresses these limitations through a comprehensive multi-layered detection framework.

## Future Enhancements

* Explainable AI using Grad-CAM
* Mobile application integration
* Real-time browser extension
* Threat intelligence integration
* Multi-class phishing attack classification

## Team Members

* URL Detection Module
* QR Code Detection Module
* Django Web Development
* Testing and Documentation

## License

This project is developed for educational and research purposes.

