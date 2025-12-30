
# 🛡️ ShieldEye ComplianceScan

![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python)
![PyQt6](https://img.shields.io/badge/PyQt6-UI-green?logo=qt)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**See the threats before they see you**

---

## ✨ Features

- 🖥️ **Modern GUI:** Clean, green-themed interface (PyQt6)
- 🔒 **Web Vulnerability Scanning:**
  - SSL/TLS certificate validation
  - Security headers (CSP, HSTS, etc.)
  - Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
  - Outdated technologies (e.g. jQuery, WordPress)
  - Insecure form handling
- 📋 **Compliance Checks:**
  - **GDPR:** Privacy policy link detection
  - **PCI-DSS:** Password field autocomplete check
  - **ISO 27001:** `security.txt` file presence
- 🗺️ **Visual Site Map:** Network graph of scanned pages
- 📄 **PDF Report Generation:** Professional, scored security reports
- ⚡ **Asynchronous Scanning:** Responsive, multi-threaded architecture

---


## 🚀 Tech Stack

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/PyQt6-UI-green?logo=qt&logoColor=white" alt="PyQt6" />
  <img src="https://img.shields.io/badge/BeautifulSoup-4.x-yellow?logo=beautifulsoup&logoColor=white" alt="BeautifulSoup" />
  <img src="https://img.shields.io/badge/requests-2.x-0052CC?logo=python&logoColor=white" alt="requests" />
  <img src="https://img.shields.io/badge/networkx-2.x-00B894?logo=python&logoColor=white" alt="networkx" />
  <img src="https://img.shields.io/badge/matplotlib-3.x-1158c7?logo=python&logoColor=white" alt="matplotlib" />
  <img src="https://img.shields.io/badge/pdfkit-1.x-FFB74D?logo=python&logoColor=white" alt="pdfkit" />
</p>

---

## 🖼️ Preview

<img width="1012" height="933" alt="Screenshot_20250730_215515" src="https://github.com/user-attachments/assets/7c5d5be3-4cae-468b-9a66-43ec4e0f17e1" />

---

## � Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/exiv703/ShieldEye_ComplianceScan.git
   cd ShieldEye_ComplianceScan
   ```
2. **Install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. **Install `wkhtmltopdf`:**
   PDF export requires [wkhtmltopdf](https://wkhtmltopdf.org/downloads.html) installed and available in your PATH.

---

## 🤖 Usage

```bash
python3 main.py
```

---

## 🎨 Design & Aesthetic

- **Primary Color:** `#00B894` (vibrant green)
- **Dark backgrounds:** For clarity and reduced eye strain
- **Monospaced font:** `Cutive Mono` for professional readability

---

## 🌱 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## � License

This project is licensed under the MIT License.
