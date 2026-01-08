# Filin Web Vulnerability Scanner

<div>
<pre>
 ,     ,        _______  ___   ___      ___   __    _                       
 )\___/(       |       ||   | |   |    |   | |  |  | |             
{(@)v(@)}      |    ___||   | |   |    |   | |   |_| |          .___, 
 {|~~~|}       |   |___ |   | |   |    |   | |       |       ___('v')___
 {/^^^\}       |    ___||   | |   |___ |   | |  _    |       `"-\._./-"'
  `m-m`        |   |    |   | |       ||   | | | |   |           ^ ^
               |___|    |___| |_______||___| |_|  |__|
</pre>
</div>

<p align="center">
  <em>An advanced, modular, and AI-powered web vulnerability scanner with a user-friendly local web interface.</em>
</p>

<p align="center">
    <a href="https://github.com/HaruShinono/Filin-Web-Vulnerability-Scanner/blob/main/LICENSE"><img src="https://img.shields.io/github/license/HaruShinono/Filin-Web-Vulnerability-Scanner?style=for-the-badge" alt="License"></a>
    <a href="https://github.com/HaruShinono/Filin-Web-Vulnerability-Scanner"><img src="https://img.shields.io/github/stars/HaruShinono/Filin-Web-Vulnerability-Scanner?style=for-the-badge&logo=github" alt="Stars"></a>
    <a href="https://github.com/HaruShinono/Filin-Web-Vulnerability-Scanner/issues"><img src="https://img.shields.io/github/issues/HaruShinono/Filin-Web-Vulnerability-Scanner?style=for-the-badge&logo=github" alt="Issues"></a>
</p>

Filin is a comprehensive security tool designed to automate the process of web vulnerability scanning. It combines a powerful Python backend, integrations with industry-standard security tools, and an intuitive web UI to provide a seamless and effective security assessment experience.

## Key Features

-   **Modular Architecture:** Easily extendable with custom Python modules for specific vulnerability checks.
-   **Local Web Interface:** Manage scans and view results through a clean, real-time web dashboard running on `http://127.0.0.1:5000`.
-   **Advanced Integrations:** Leverages the power of external tools like **Nmap**, **SQLMap**, and **Nuclei** for deep infrastructure and vulnerability analysis.
-   **AI-Powered Remediation:** Utilizes a local LLM (Ollama) to provide AI-generated explanations and code fixes for discovered vulnerabilities.
-   **Authenticated Scanning:** Supports cookie-based authentication to scan protected areas of web applications.
-   **Professional Reporting:** Generate detailed scan reports in PDF format for documentation and distribution.
-   **Smart Analysis:** Implements verification and deduplication logic to reduce false positives and eliminate redundant findings.

## Installation

Filin is designed to run on Linux-based systems (Kali Linux is recommended).

### 1. Prerequisites (External Tools)

Before installing the application, ensure you have the following tools installed and available in your system's PATH.

```bash
# Update package list
sudo apt update

# Install Nmap, Nuclei, SQLMap, and DNSRecon
sudo apt install nmap nuclei sqlmap dnsrecon -y

# Install WeasyPrint dependencies for PDF reporting
sudo apt install python3-pip python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0 -y
```

### 2. Local Language Model (Ollama)

Filin uses a local AI model for remediation advice.

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull the CodeLlama model (this will download several GB)
ollama pull codellama:7b

# 3. (Optional) Start the Ollama server if it's not running
ollama serve
```

### 3. Application Setup

```bash
# 1. Clone the repository
git clone https://github.com/HaruShinono/Filin-Web-Vulnerability-Scanner.git
cd Filin-Web-Vulnerability-Scanner

# 2. Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install required Python packages
pip install -r requirements.txt
```

## Usage

1.  **Start the Web Server:**
    
    Make sure your virtual environment is activated, then run:
    ```bash
    python -m flask run
    ```

2.  **Access the Dashboard:**
    
    Open your web browser and navigate to **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.

3.  **Run a Scan:**
    
    -   Enter the target URL into the "New Scan" form.
    -   (Optional) If you need to perform an authenticated scan, paste the target application's session cookies into the "Authentication Cookies" field.
    -   Click "Start Scan". You will be redirected to a real-time results page.

## Project Structure

```
Filin-Web-Vulnerability-Scanner/
├── app.py                  # Main Flask application entry point
├── factory.py              # Application factory for creating Flask app
├── routes.py               # Defines all web routes and API endpoints
├── tasks.py                # Background worker logic for running scans
├── models.py               # SQLAlchemy database models
├── config/                 # Configuration files (payloads, settings)
├── integrations/           # Modules for integrating external tools (Nmap, Nuclei, etc.)
├── scanner_core/           # Core Python-based scanning engine and testers
├── static/                 # CSS, JavaScript, and image assets
├── templates/              # HTML templates for the web interface
├── requirements.txt        # Python package dependencies
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature`).
3.  Commit your changes (`git commit -m 'Add some feature'`).
4.  Push to the branch (`git push origin feature/your-feature`).
5.  Open a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
