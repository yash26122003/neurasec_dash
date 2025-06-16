
# 🔒 Phishing URL Detection Dashboard

This project is a **Streamlit-based web application** designed to analyze URLs and detect **potential phishing attacks** using a set of rule-based features and threat intelligence techniques. It aims to help users evaluate suspicious links in real-time.

## 🚀 Features

- 🌐 **URL Input Interface** — Easily input and analyze any URL.
- 🕵️‍♂️ **Feature Extraction** — Extracts technical features from URLs like:
  - IP-based URLs (IPv4, IPv6, decimal, hex, octal)
  - SSL certificate validity
  - WHOIS data
  - DNS records
  - URL entropy, domain age, and redirection depth
- 📈 **Visualization** — Uses Plotly for displaying threat patterns and distributions.
- 🧠 **Heuristics-Based Detection** — Checks against phishing heuristics using Python and domain knowledge.
- 📊 **Interactive Dashboard** — Built with Streamlit for real-time analysis.

## 🧰 Tech Stack

- Python 🐍
- Streamlit 📺
- Plotly 📊
- BeautifulSoup 🌐
- DNS, WHOIS, SSL, Socket Libraries
- Custom Feature Extraction Scripts

## 📁 Project Structure

```
.
├── dashboard.py         # Main Streamlit dashboard
├── paste.py             # Helper functions for feature extraction
├── requirements.txt     # Dependencies
└── README.md            # Project overview (this file)
```

## 🔧 Setup Instructions

1. **Clone the repository**  
   ```bash
   git clone https://github.com/yourusername/phishing-url-detector.git
   cd phishing-url-detector
   ```

2. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**  
   ```bash
   streamlit run dashboard.py
   ```

## 🧪 How It Works

1. The user submits a URL via the dashboard.
2. The backend extracts:
   - URL structure features (length, special characters, etc.)
   - WHOIS data (domain age, registrar)
   - SSL Certificate info
   - DNS & IP patterns
3. These features are analyzed to detect red flags typical in phishing attempts.

## ⚠️ Disclaimer

This tool is built for **educational and research purposes only**. Always verify results with a professional cybersecurity team before taking any action based on the results.

## 👨‍💻 Author

Made with ❤️ by [Your Name]
