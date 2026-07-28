# 🛡️ Cyber Dashboard

A self-hosted OSINT and recon toolkit that brings together the most common tools a security researcher reaches for — username enumeration, IP/domain intelligence, port scanning, threat-intel lookups, and more — behind a single web dashboard.

Built with a **Node.js/Express** backend, a **vanilla JS** frontend, and a handful of **Python** helper scripts, with live data from **Shodan**, **VirusTotal**, and **AbuseIPDB**.

---

## ✨ Features

| Module | What it does |
|---|---|
| 🔍 Username Search | Checks a username's presence/footprint across platforms |
| 🌐 IP Lookup | Geolocation and ISP info for any IPv4 address |
| 🖥️ Domain Intelligence | WHOIS-style lookup for a target domain |
| 📡 Port Scanner | Scans common ports on an IP or domain |
| 🖼️ Image Metadata Extractor | Pulls EXIF/metadata from uploaded images |
| 🕸️ DNS Records Lookup | Fetches A, MX, TXT, NS, and other DNS records |
| 🔒 SSL/TLS Certificate Inspector | Inspects a domain's TLS certificate details |
| 🗺️ Subdomain Enumeration | Discovers subdomains for a given domain |
| ⏳ Wayback Machine History | Pulls historical snapshots from the Internet Archive |
| 🧩 Tech Stack Fingerprinter | Detects the frameworks/technologies a website runs on |
| 📶 Shodan Device Lookup | Queries Shodan's internet-connected device database |
| 🦠 VirusTotal Reputation Lookup | Checks a domain, IP, URL, or file hash against VirusTotal |
| 🚨 AbuseIPDB Check | Retrieves an IP's abuse confidence score and report history |
| ✉️ Email Spam/Phishing Analyzer | Scores raw email source (headers included) 0–10 for phishing risk, with a transparent breakdown |
| 🎯 Domain Recon Toolkit | Typosquat detection + reverse WHOIS in one panel |

---

## 🏗️ Tech Stack

- **Backend:** Node.js, Express, Axios, Multer, Mailparser
- **Frontend:** HTML, CSS, vanilla JavaScript
- **Scripting:** Python (username search, domain lookup, port scanning, metadata extraction)
- **Threat Intel APIs:** Shodan, VirusTotal, AbuseIPDB

---

## 📂 Project Structure

```
cyber-dashboard/
├── backend/
│   ├── server.js          # Express API — all routes/endpoints
│   ├── package.json
│   └── env.example        # Template for required API keys
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── python-tools/
│   ├── username_search.py
│   ├── domain_lookup.py
│   ├── port_scanner.py
│   ├── metadata_tool.py
│   └── requirements.txt   # Python dependencies for the tools above
└── start.sh
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+ recommended)
- Python 3
- Free API keys from [Shodan](https://account.shodan.io/register), [VirusTotal](https://www.virustotal.com/gui/join-us), and [AbuseIPDB](https://www.abuseipdb.com/register)

### Setup

```bash
# Clone the repo
git clone https://github.com/<your-username>/cyber-dashboard.git
cd cyber-dashboard

# Install backend dependencies
cd backend
npm install

# Install Python dependencies for the recon scripts
cd ../python-tools
pip install -r requirements.txt

# Configure environment variables
cd ../backend
cp env.example .env
# then edit .env and add your Shodan / VirusTotal / AbuseIPDB API keys

# Start the server
npm start
```

Then open `frontend/index.html` in your browser (or serve the `frontend/` folder with any static file server).

> ⚠️ **Never commit your `.env` file.** It contains live API keys tied to your accounts and rate limits.

---

## 🔐 Security Notes

- All user-supplied input (usernames, domains, IPs) is validated against strict regex patterns before being passed to any subprocess.
- Python scripts are invoked via `execFile` (not `exec`), so no shell is spawned and shell-injection via crafted input isn't possible.
- This tool is intended for **authorized security research and personal OSINT use only** — always get proper authorization before scanning or probing infrastructure you don't own.

---

## 📌 Disclaimer

This project is for educational and authorized security testing purposes only. The author is not responsible for any misuse of this tool. Always comply with applicable laws and obtain explicit permission before testing any system you do not own.

---

## 📄 License

MIT License — feel free to fork, use, and build on this.
