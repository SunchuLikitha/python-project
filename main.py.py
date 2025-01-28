import pandas as pd
import re
import requests
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, classification_report
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import whois
from datetime import datetime

# Expanded and balanced dataset
data = {
    'message': [
        # Spam examples
        "Congratulations! You've won a $1000 Walmart gift card. Go to http://bit.ly/123456",
        "Win $10,000 now! Click here: http://spammy-offer.com",
        "Claim your free gift now at http://claim-prize.com",
        "Your bank account has been locked. Login at http://secure-bank.com to unlock.",
        "Get a loan with 0% interest today. Apply at http://fastloans.com!",
        "Urgent! Your account will be suspended if not verified: http://phishingsite.com",
        # Safe examples
        "Hey, are we still on for the meeting tomorrow?",
        "Hi, can we meet for lunch tomorrow?",
        "Your package will be delivered by 2 PM.",
        "Reminder: Your appointment is scheduled for Monday.",
        "Let's grab some coffee this weekend.",
        "Please review the attached document for tomorrow's meeting."
    ],
    'label': ['spam', 'spam', 'spam', 'spam', 'spam', 'spam', 'safe', 'safe', 'safe', 'safe', 'safe', 'safe']
}

# Ensure both lists have the same length
if len(data['message']) != len(data['label']):
    raise ValueError("The length of messages and labels must be the same.")

# Create a DataFrame
df = pd.DataFrame(data)

# Feature extraction using TF-IDF with n-grams
vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words='english')
X = vectorizer.fit_transform(df['message'])

# Labels (spam or safe)
y = df['label']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

# Train models
naive_bayes = MultinomialNB(alpha=0.5)
random_forest = RandomForestClassifier(n_estimators=200, random_state=42)

naive_bayes.fit(X_train, y_train)
random_forest.fit(X_train, y_train)

# Ensemble model combining Naive Bayes and Random Forest
ensemble_model = VotingClassifier(estimators=[
    ('naive_bayes', naive_bayes),
    ('random_forest', random_forest)
], voting='hard')
ensemble_model.fit(X_train, y_train)

# Function to predict if a message is spam
def predict_spam(message):
    try:
        message_transformed = vectorizer.transform([message])
        prediction = ensemble_model.predict(message_transformed)
        print(f"Message: {message}")
        print(f"Prediction: {prediction[0]}")
        return prediction[0]
    except Exception as e:
        print(f"Error in prediction: {e}")
        return "error"

# Function to check if an email is spam
def check_email_spam(subject, body):
    email_content = f"Subject: {subject} {body}"
    return predict_spam(email_content)

# Function to extract URL-based features
def extract_url_features(url):
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        domain_age = (datetime.now() - creation_date).days if creation_date else 0
        url_length = len(url)
        suspicious_chars = len(re.findall(r'[!@#$%^&*]', url))
        return {'domain_age': domain_age, 'url_length': url_length, 'suspicious_chars': suspicious_chars}
    except Exception as e:
        print(f"Error extracting URL features: {e}")
        return {'domain_age': 0, 'url_length': len(url), 'suspicious_chars': len(re.findall(r'[!@#$%^&*]', url))}

# Function to check if a website is spam
def check_website_spam(url):
    try:
        # Fetch website content
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract text from the website
        website_text = soup.get_text()
        url_features = extract_url_features(url)

        # Combine URL features and website content analysis
        url_score = "High risk" if url_features['domain_age'] < 30 or url_features['suspicious_chars'] > 5 else "Low risk"
        text_prediction = predict_spam(website_text[:1000])  # Analyze the first 1000 characters

        return f"Website Text: {text_prediction}, URL Risk: {url_score}"
    except Exception as e:
        print(f"Error fetching the website: {e}")
        return "Could not check the website"

# GUI code with tkinter
def main_gui():
    # Create main window
    window = tk.Tk()
    window.title("AI-Enabled Phishing Detection Plugin")
    window.geometry("600x500")

    # Function to handle message spam check
    def check_message_spam():
        message = message_entry.get()
        if message:
            result = predict_spam(message)
            messagebox.showinfo("Result", f"The message is: {result}")
        else:
            messagebox.showwarning("Input Error", "Please enter a message.")

    # Function to handle email spam check
    def check_email_spam_gui():
        subject = email_subject_entry.get()
        body = email_body_entry.get("1.0", tk.END).strip()
        if subject and body:
            result = check_email_spam(subject, body)
            messagebox.showinfo("Result", f"The email is: {result}")
        else:
            messagebox.showwarning("Input Error", "Please enter both subject and body.")

    # Function to handle website spam check
    def check_website_spam_gui():
        url = website_entry.get()
        if url:
            result = check_website_spam(url)
            messagebox.showinfo("Result", f"The website is: {result}")
        else:
            messagebox.showwarning("Input Error", "Please enter a website URL.")

    # Create tabs for message, email, and website using ttk.Notebook
    tab_control = ttk.Notebook(window)

    # Message Spam Tab
    message_tab = ttk.Frame(tab_control)
    tab_control.add(message_tab, text='Message Spam')

    tk.Label(message_tab, text="Enter Message:").pack(pady=10)
    message_entry = tk.Entry(message_tab, width=50)
    message_entry.pack(pady=10)

    check_message_btn = tk.Button(message_tab, text="Check Message", command=check_message_spam)
    check_message_btn.pack(pady=10)

    # Email Spam Tab
    email_tab = ttk.Frame(tab_control)
    tab_control.add(email_tab, text='Email Spam')

    tk.Label(email_tab, text="Enter Email Subject:").pack(pady=10)
    email_subject_entry = tk.Entry(email_tab, width=50)
    email_subject_entry.pack(pady=10)

    tk.Label(email_tab, text="Enter Email Body:").pack(pady=10)
    email_body_entry = tk.Text(email_tab, height=10, width=50)
    email_body_entry.pack(pady=10)

    check_email_btn = tk.Button(email_tab, text="Check Email", command=check_email_spam_gui)
    check_email_btn.pack(pady=10)

    # Website Spam Tab
    website_tab = ttk.Frame(tab_control)
    tab_control.add(website_tab, text='Website Spam')

    tk.Label(website_tab, text="Enter Website URL:").pack(pady=10)
    website_entry = tk.Entry(website_tab, width=50)
    website_entry.pack(pady=10)

    check_website_btn = tk.Button(website_tab, text="Check Website", command=check_website_spam_gui)
    check_website_btn.pack(pady=10)

    # Add tabs to window
    tab_control.pack(expand=1, fill='both')

    # Start the GUI event loop
    window.mainloop()

# Run the GUI
if __name__ == "__main__":
    main_gui()
