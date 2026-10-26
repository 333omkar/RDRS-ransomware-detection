RDRS: Ransomware Detection & Response System

A real-time ransomware detection and response system built with Flask and Socket.IO. It monitors files, deploys honeypot decoys, analyzes process behavior, and shows everything on a SOC-style live dashboard.

Disclaimer: This is an educational and portfolio project. It contains no real ransomware. Any test scripts only simulate file-modification behavior in a controlled folder.

Dashboard

Features
File monitoring: watches directories for suspicious activity such as mass modification, renaming, and extension changes.
Honeypot decoys: plants decoy files and flags any process that touches them.
Process behavior analysis: identifies processes showing ransomware-like behavior.
Real-time dashboard: live alerts pushed to a SOC-style interface through Socket.IO.
Response actions: surfaces and acts on detected threats (see the Response section).
How It Works
File system events ---+
Honeypot access -------+--> Detection engine --> Alert --> Socket.IO --> Dashboard
Process behavior ------+                                   |
                                                           +--> Response action
Monitors collect file-system events, honeypot access, and process activity.
The detection engine scores the activity against ransomware indicators.
Alerts are pushed to the dashboard in real time.
A response action is triggered for confirmed threats.
Tech Stack
Component	Purpose
Python / Flask	Web application and API
Flask-SocketIO	Real-time alert streaming
watchdog (or similar)	File system monitoring
psutil (or similar)	Process analysis
HTML / CSS / JavaScript	Dashboard UI

Edit this table so it matches the libraries in your requirements.txt.

Project Structure
.
├── app.py
├── requirements.txt
├── templates/
├── static/
└── docs/
    └── screenshots/

Update this tree to match your real folders.

Installation
Prerequisites
Python 3.9 or later
pip
Setup
bash
git clone https://github.com/333omkar/RDRS-ransomware-detection.git
cd RDRS-ransomware-detection

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / macOS

pip install -r requirements.txt
Run
bash
python app.py

Open http://localhost:5000 in your browser.

Testing

Use only a dedicated test folder, never real data.

Start RDRS and point it at a test directory.
Run the included simulation script (or create and rapidly modify many files).
Touch a honeypot decoy file.
Confirm that alerts appear on the dashboard in real time.
Screenshots
Dashboard	Honeypot alert	Process analysis
dashboard	honeypot	process
MITRE ATT&CK Mapping
Technique	ID
Data Encrypted for Impact	T1486
Inhibit System Recovery	T1490

Keep only the techniques your project actually detects.

Limitations
Built for learning and demonstration, not production use.
Detection is behavior and heuristic based and can produce false positives.
Tested on a limited set of simulated scenarios.
Future Improvements
Machine-learning-based anomaly detection
Automatic process isolation and file rollback
Integration with a SIEM such as Wazuh
Email or Slack notifications
Author

Omkar Chavan LinkedIn | GitHub
