# ThreatPulse 🛡️

A lightweight, real-time cyber threat intelligence dashboard with both web and CLI interfaces. ThreatPulse aggregates data from multiple open-source threat intelligence feeds to provide actionable insights about current cyber threats.

## Features 🌟

- Real-time threat intelligence dashboard
- Command-line interface for quick queries
- Multiple data sources (AlienVault OTX, PhishTank, AbuseIPDB)
- Automatic data refresh
- Dark mode support
- Export capabilities (JSON/CSV)
- Zero configuration required

## Quick Start 🚀

1. Clone the repository:
```bash
git clone https://github.com/yourusername/threatpulse.git
cd threatpulse
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the web dashboard:
```bash
python app.py
```

The dashboard will be available at `http://localhost:5000`

## CLI Usage 💻

```bash
# View recent malware campaigns
python -m threatpulse.cli malware

# Check recent phishing sites
python -m threatpulse.cli phishing

# List malicious IPs
python -m threatpulse.cli ips

# Export data to JSON
python -m threatpulse.cli malware --format json
```

## Data Sources 📊

- AlienVault Open Threat Exchange (OTX)
- PhishTank
- AbuseIPDB
- CIRCL TAXII Feeds

## Project Structure 📁

```
threatpulse/
├── api/                # API integrations
├── cli/               # CLI implementation
├── static/            # Static assets
├── templates/         # Web dashboard templates
├── app.py            # Web app entry point
└── requirements.txt  # Python dependencies
```

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.

## Security 🔒

This project uses only public APIs and does not store any sensitive data. All data is read-only and validated before display.
