# Web Vulnerability Scanner
A high‑performance offensive security toolkit designed for automated
discovery of web vulnerabilities. Built for security researchers,
penetration testers, and red-team operators who require real‑time
insights, modular exploit logic, and a clean local UI for managing
reconnaissance operations.

## 🔥 Core Capabilities

-   **Local Web Interface (127.0.0.1:5000):** Operate like a lightweight
    Nessus --- manage scans, review findings, and control tasks from a
    browser-based dashboard.
-   **Async Scan Engine:** Heavy scans execute in background workers,
    ensuring the UI remains responsive even under aggressive load.
-   **Live Intelligence Feed:** Vulnerability findings stream to the
    dashboard in real time --- no manual refresh, no delays.
-   **Modular Exploit Framework:** Add new vulnerability modules,
    payloads, or exploit logic with minimal boilerplate.
-   **Central Payload Registry:** All attack payloads, signatures, and
    behavioral configs stored in a unified YAML file.
-   **Persistent Scan Database:** SQLite backend preserves scan history,
    timeline logs, and full vulnerability reports for later analysis.

## 🛠 Installation

``` bash
git clone https://github.com/HaruShinono/Simple-Web-Vulnerability-Scanner.git
cd Simple-Web-Vulnerability-Scanner
```

### Virtual Environment (Recommended)

``` bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### Dependency Installation

``` bash
pip install -r requirements.txt
```

## 🚀 Usage Workflow

### 1. Launch the System

``` bash
flask run
```

(or `python app.py` depending on configuration)

### 2. Access the Web Console

Open: **http://127.0.0.1:5000**

### 3. Initiate an Offensive Scan

-   Enter the target URL\
-   Trigger **Start Scan**\
-   Monitor the live output stream and analyze discovered vectors

## 🧩 Extending the Framework

-   Create a new module in `/modules/`\
-   Implement `run(target)` with detection or exploit logic\
-   Register payloads/signatures in `payloads.yaml`\
-   The engine auto-loads modules on startup

## 📌 Notes for Security Researchers

-   Designed for controlled security assessments\
-   Do **NOT** use on systems without authorization\
-   Ideal for lab environments, CTF automation, recon pipelines, and
    teaching offensive security methodologies

## 📄 License

MIT License

Copyright (c) 2025 Haru Shinono

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

