# 🛡️ AI Phishing & Threat Detector

An intelligent, AI-powered cybersecurity web application designed to analyze suspicious URLs, detect phishing indicators, and provide real-time threat evaluations powered by **Google Gemini** and **Python NiceGUI**.

---

## 🌐 Live Application

[![Live Demo](https://img.shields.io/badge/Live_Demo-Visit_on_Render-10b981?style=for-the-badge&logo=render&logoColor=white)](https://ai-phising-detector-m5z3.onrender.com)

🔗 **Website:** [https://ai-phising-detector-m5z3.onrender.com](https://ai-phising-detector-m5z3.onrender.com)

---

## ✨ Key Features

- 🔍 **AI Threat Analysis:** Evaluates URLs and suspicious links using Google Gemini (`google-genai`) for real-time security reasoning.
- 🌐 **IP & Domain Parsing:** Extracts host data, identifies IP formats, and highlights potential spoofing or typosquatting attempts.
- 🔐 **Secure Authentication:** User sign-up and sign-in protected with `bcrypt` password hashing.
- 📜 **Scan History & Audit Logs:** Tracks previous security checks and breach counters stored in a MySQL database.
- 🎨 **Cyber Emerald UI:** Modern, responsive dark-mode interface built natively in Python using NiceGUI.

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| **Frontend & UI** | [NiceGUI](https://nicegui.io/) (Python Web UI) |
| **AI Intelligence** | [Google Gemini API](https://ai.google.dev/) (`google-genai`) |
| **Database** | MySQL / TiDB Cloud |
| **Authentication** | Bcrypt |
| **Email Service** | [Resend](https://resend.com/) |
| **Hosting & Deployment** | [Render](https://render.com/) |

---

## 🚀 Local Setup & Installation

### Prerequisites
- Python 3.10+
- MySQL / TiDB Database
- Google Gemini API Key

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ShaikhVaiz/AI-Phising-Detector.git
   cd AI-Phising-Detector
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up Environment Variables:**
   Create a `.env` file in the project root:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   DB_PASSWORD=your_database_password_here
   ```

5. **Start the Application:**
   ```bash
   python dashboard.py
   ```
   Open your browser and navigate to `http://localhost:8080`.

---

## 👤 Author

- **Shaikh Vaiz** – [@ShaikhVaiz](https://github.com/ShaikhVaiz)
