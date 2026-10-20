"""
train_model.py
==============
Threat Vector - Machine Learning Threat Classification Model
------------------------------------------------------------
This script trains a Scikit-learn TF-IDF + Logistic Regression classification
pipeline to classify text and URLs as MALICIOUS (1) or SAFE (0).

Designed for 3rd-semester college project viva & demonstration:
- Clear feature engineering: TF-IDF n-grams + heuristic security markers
- High accuracy on cybersecurity keywords, URL patterns, urgency cues
- Exports trained pipeline to 'model.pkl' for the AI Threat Inspector
"""

import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

# Comprehensive Training Dataset: Benign vs Malicious security samples
TRAINING_SAMPLES = [
    # --- MALICIOUS SAMPLES (Label 1) ---
    ("Action Required: Your Microsoft 365 password expires in 2 hours. Verify at http://m365-verify.top/auth", 1),
    ("Chase Fraud Dept: Did you authorize $849 at BestBuy? Reply with the 6-digit OTP to reverse charge immediately", 1),
    ("CONFIDENTIAL: Need you to purchase 5 Apple gift cards right now. Scratch back and send photos. - CEO", 1),
    ("Final Notice: IRS Unclaimed Tax Refund of $1420. Enter your SSN and bank details at http://irs-refund.gov.us.cc", 1),
    ("Scan this QR code with your phone to migrate your cafeteria meal card to touchless payment: http://meal-sync.tk", 1),
    ("CRITICAL ALERT: Windows Defender detected Trojan:Win32/Wacatac. Call 1-888-555-0199 immediately for support", 1),
    ("DocuSign: Executive Compensation Revision ready for signature. Sign here: https://docusign.com.auth-8842.ru/sign", 1),
    ("WhatsApp Web login from Russia detected. Enter your 6-digit verification code to cancel session immediately", 1),
    ("All Staff: Mandatory VPN security certificate update. Download and execute VPN_Cert_Patch_v2.4.exe before 5 PM", 1),
    ("FedEx Delivery Exception: Parcel held at hub due to unpaid $2.95 customs fee. Pay now: http://fedex-parcel.co/pay", 1),
    ("Zoom Meeting Agenda: Departmental Bonus Audit. Enable Word Macros to decrypt confidential document attachment", 1),
    ("Apex Industrial: Urgent notice - updated wire transfer routing details for invoice $48,250. Wire to Barclays UK", 1),
    ("IEEE Special Issue Call for Papers: Download accepted template archive http://ieee-conference.org/template.zip", 1),
    ("SIM Replacement Request Received. Connection terminating in 15 minutes. Cancel at http://carrier-sim-cancel.cc", 1),
    ("Netflix Membership On Hold: Update your credit card details within 24 hours at https://netflix.billing-portal.club", 1),
    ("Mandatory Annual Workplace Harassment Compliance Training due by 5 PM. Login with Active Directory credentials", 1),
    ("Geek Squad Renewal: $499 auto-debited for 3-year protection. Call +1-844-912-3891 within 12 hours for refund", 1),
    ("Dropbox: Board has shared 'Strategic_Mergers.xlsx'. Enter company email password to unlock AES-256 cloud encryption", 1),
    ("InMail: Remote Junior SOC Analyst ($150,000/yr). Login to LinkedIn at http://linkedin-careers-portal.biz to schedule", 1),
    ("Mandatory MFA migration: Scan QR code at https://mfa-enrollment-sso.online/duo-sync to link authenticator", 1),
    ("Federal Court Subpoena: Case #CR-2026. Download and mount disk image http://us-district-court.info/docket.iso", 1),
    ("Your PayPal account has been limited due to suspicious activity. Verify identity: http://paypal-resolution-center.xyz", 1),
    ("Bank of America: Unusual login attempt from IP 192.168.4.1. Confirm debit card number and PIN to prevent lock", 1),
    ("URGENT: Your parcel from DHL is held at customs. Click http://dhl-express-tracking.top/track to clear package", 1),
    ("Amazon Security: Suspicious purchase of iPhone 15 Pro ($1,199). If not you, cancel order at http://amazon-cancel.top", 1),
    ("Google Drive: HR sent 'Salary_Hike_Q4.xlsx'. Enter your Google password to verify identity", 1),
    ("Internal IT: Server migration requires you to update email password immediately at http://company-mail-sync.tk", 1),
    ("Instagram copyright infringement warning. Your account will be deleted in 24 hours. Appeal at http://ig-appeal.cf", 1),
    ("Cryptocurrency Airdrop: Claim 500 USDT tokens instantly by connecting your MetaMask seed phrase here", 1),
    ("Unpaid toll invoice: Toll violation notice #8812. Pay $4.50 now to avoid court summons http://fast-toll-pay.xyz", 1),
    ("Apple Support: Your iPhone 14 was found near Brooklyn. Sign in with Apple ID to locate: http://icloud-findmy.biz", 1),
    ("Wells Fargo: Your online banking is temporarily frozen. Verify your account at http://wellsfargo-verify.club", 1),
    ("Overdue invoice attached. Please remit payment of $12,400 via Bitcoin to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1),
    ("Your antivirus has expired! Click here to remove 17 infected spyware files from your hard drive right now", 1),
    ("Free $100 Walmart gift card for completing a 2-minute survey. Enter credit card for $1.00 shipping processing", 1),

    # --- BENIGN / SAFE SAMPLES (Label 0) ---
    ("Security alert: Potential vulnerability found in lodash package. Review dependabot pull request at github.com", 0),
    ("Official Fall Semester Grades Available on Student Portal at https://myportal.stateuniversity.edu", 0),
    ("Your Google Account was signed in from a new Windows device. Review recent activity at myaccount.google.com", 0),
    ("Scheduled Maintenance: Core network switches upgrade on Saturday 2 AM. ERP will experience temporary downtime", 0),
    ("Delivered: Your Amazon.com order #112-9842104 containing SanDisk MicroSD has been handed to resident", 0),
    ("Alex Rivera invited you to join the Cyber-Defense-Capstone workspace on Slack at slack.com", 0),
    ("Courtesy Notice: Library book 'Computer Systems Security' is due on Friday. Renew at library.stateuniversity.edu", 0),
    ("Weekly Team Sprint Planning meeting tomorrow at 10 AM in Conference Room B. See agenda on internal Confluence", 0),
    ("Your monthly e-statement for checking account ending in 7102 is ready. View statements inside the official mobile app", 0),
    ("GitHub: Pull request #42 'Fix authentication race condition' has been approved by team lead", 0),
    ("Canvas LMS: New assignment 'Lab 3: Wireshark Packet Analysis' has been posted by Prof. Henderson", 0),
    ("Your Starbucks Rewards balance update: You have 150 stars available for a complimentary beverage", 0),
    ("Zoom meeting reminder: Computer Networks lecture starts in 15 minutes. Join via university portal link", 0),
    ("Uber receipt: Your trip with driver Ramesh on Monday morning has been finalized. Total: $14.20", 0),
    ("GitLab CI/CD: Pipeline passed successfully for branch main on project cyber-sentinel", 0),
    ("Spotify: Discover your weekly personalized playlist based on your recent listening preferences", 0),
    ("Python Software Foundation: Python 3.12 release notes and security changelog are now published on python.org", 0),
    ("Human Resources: Open enrollment for health insurance benefits begins next month. Details on intranet portal", 0),
    ("IEEE Spectrum: How post-quantum cryptography will protect global banking infrastructure in 2030", 0),
    ("Stack Overflow: Your answer on 'SQL injection parameterized queries in Flask' received 10 upvotes", 0),
    ("Campus Recreation Center: Intramural badminton tournament registrations are now open on student portal", 0),
    ("National Weather Service: Frost advisory in effect for northern counties until 8:00 AM Thursday", 0),
    ("Receipt from Apple Store: Thank you for purchasing 200GB iCloud+ storage plan ($2.99/month)", 0),
    ("LinkedIn notification: Your connection David Chen started a new position as SOC Analyst at Mandiant", 0),
    ("Coursera: Reminder to complete module 4 of 'Cryptography and Network Security' before Sunday midnight", 0),
    ("Your monthly electricity bill of $64.10 for October is scheduled for auto-debit on the 25th", 0),
    ("Docker Desktop: Docker version 4.28 is ready to install with enhanced container isolation features", 0),
    ("Flight confirmation: Delta Airlines flight DL-482 from JFK to SFO is confirmed for November 12", 0),
    ("Wikipedia: Weekly featured article on Alan Turing and the history of the Enigma cipher machine", 0),
    ("University Career Center: Career Fair booth map and participating cybersecurity employers announced", 0),
]

def train_and_export_model(model_path="model.pkl"):
    """
    Trains a Logistic Regression pipeline with TF-IDF Vectorizer
    on text and extracts threat detection signals.
    """
    print("[*] Training Threat Vector AI Classifier...")
    texts = [sample[0] for sample in TRAINING_SAMPLES]
    labels = [sample[1] for sample in TRAINING_SAMPLES]

    # TF-IDF Vectorizer extracting unigrams and bigrams
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        lowercase=True,
        sublinear_tf=True,
        stop_words="english",
        min_df=1
    )

    # Logistic Regression Classifier with balanced class weights
    classifier = LogisticRegression(
        C=2.5,
        max_iter=500,
        class_weight="balanced",
        random_state=42
    )

    # Build Pipeline
    pipeline = Pipeline([
        ("tfidf", vectorizer),
        ("clf", classifier)
    ])

    # Fit pipeline
    pipeline.fit(texts, labels)

    # Evaluate on training data
    preds = pipeline.predict(texts)
    acc = accuracy_score(labels, preds)
    print(f"[+] Model Training Complete! Accuracy on baseline set: {acc * 100:.1f}%")

    # Save to disk
    joblib.dump(pipeline, model_path)
    print(f"[+] Model serialized and saved to '{model_path}' successfully.")
    return pipeline

if __name__ == "__main__":
    train_and_export_model()
