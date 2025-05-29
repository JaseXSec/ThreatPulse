# ThreatPulse 🛡️

A lightweight, real-time cyber threat intelligence dashboard and CLI tool. ThreatPulse aggregates data from multiple open-source threat intelligence feeds to provide actionable insights about current cyber threats.

## Features

- 🌐 Web Dashboard: Real-time visualization of cyber threats
- 📊 Threat Statistics: Track malware campaigns, phishing sites, and malicious IPs
- 🖥️ CLI Interface: Quick access to threat data from your terminal
- 🔄 Auto-refresh: Stay updated with the latest threat intelligence
- 📈 Trend Analysis: Visual representation of threat patterns
- 🔒 Security-First: Uses only public APIs and follows secure coding practices

## Quick Start

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

4. Access the dashboard at: http://localhost:8000

## CLI Usage

ThreatPulse CLI provides quick access to threat data:

```bash
# View latest malware campaigns
python -m threatpulse.cli malware

# Check recent phishing sites
python -m threatpulse.cli phishing

# List malicious IPs
python -m threatpulse.cli ips

# Export data to JSON
python -m threatpulse.cli malware --format json
```

## Data Sources

ThreatPulse aggregates data from these public threat intelligence sources:
- AlienVault OTX
- PhishTank
- AbuseIPDB
- CIRCL TAXII feeds

## Security

- Uses HTTPS for all API requests
- No authentication required - read-only access
- Data sanitization and validation
- No API keys or credentials required
- Graceful handling of rate limits and API failures

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 