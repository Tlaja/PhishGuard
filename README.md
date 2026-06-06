# 🐟 PhishGuard — Phishing Detector

> A Chrome extension for real-time automated phishing email detection.  
> Built for the **201:Go! Hackathon** by team **Phishermen**.

---

## How It Works

PhishGuard runs in the background while you browse Gmail and analyzes every email in two ways:

1. **Text Analysis** — scans for suspicious keywords commonly found in phishing emails (urgent, bank, suspended, refund, verify, etc.)
2. **VirusTotal Check** — every external link found in the email is sent to the VirusTotal API and checked against a database of known malicious URLs

If a threat is detected, a visual alert appears directly in your browser:
- 🚨 **Red alert** — link is flagged as dangerous on VirusTotal
- ⚠️ **Orange alert** — email text contains multiple suspicious keywords

---

## Installation

> The extension is not yet on the Chrome Web Store — it must be loaded manually.

1. Fork this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (top right toggle)
4. Click **Load unpacked** and select the folder containing the extension files
5. Add your VirusTotal API key to `background.js`:
   ```js
   const VT_API_KEY = 'your_api_key_here';
   ```
6. Refresh the extension on `chrome://extensions/`

---

## Supported Email Clients

| Email Client | Supported |
|---|---|
| Gmail (`mail.google.com`) | ✅ |

---

## Tech Stack

- **Chrome Extensions Manifest V3**
- **VirusTotal API v3**
- Vanilla JavaScript (content script + service worker)

---

## Project Structure

```
📁 extension/
├── manifest.json     # Extension configuration
├── background.js     # Service worker — handles VirusTotal API communication
└── content.js        # Content script — page analysis and alert rendering
```

---

## Security Notice

The VirusTotal API key **must not be hardcoded** in a production environment. For local testing, add it manually to `background.js` but **do not commit it** to GitHub.

---

## Team

**Phishermen** — 201:Go! Hackathon 2026
