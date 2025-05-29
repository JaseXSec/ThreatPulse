# ThreatPulse - Threat Intelligence Dashboard

**ThreatPulse** is a comprehensive, single-file threat intelligence dashboard that provides real-time cyber threat awareness through multiple free public APIs. It's designed to be extremely easy to install and run, requiring **just one Python command**.

![ThreatPulse Dashboard](https://img.shields.io/badge/Status-Active-green)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

### **Ease of Use** (Priority #1)
- **Single command execution**: Just run `python threatpulse.py` - that's it!
- **Auto-installs dependencies**: No manual setup required
- **Auto-opens browser**: Automatically launches your default browser
- **Auto-refresh**: Updates every 15 minutes automatically
- **Web-based**: Access via browser at `http://localhost:5000`

### **Advanced Threat Intelligence**
- **IP Geolocation**: Shows attack origins with city, country, and organization
- **Threat Attribution**: Maps threats to known APT groups and threat actors
- **Multi-source aggregation**: Collects from 9 different threat intelligence sources
- **Real-time indicators**: Malicious IPs, phishing URLs, and malware hashes
- **Live feed status**: Connection monitoring with countdown timers

### **Security First**
- Uses only **free, public APIs** (no API keys required)
- **Read-only** threat intelligence consumption
- Secure data handling and sanitization
- **HTTPS** connections to all threat feeds

### **Modern Web Dashboard**
- Professional dark theme interface
- Three-column layout showing all threat types
- Real-time charts and statistics
- Mobile-friendly responsive design
- Live status indicators for all data sources

## Quick Start

### Prerequisites
- Python 3.7 or higher
- Internet connection

### Run ThreatPulse (One Command!)
```bash
python threatpulse.py
```

That's it! The script will:
1. Check for required dependencies
2. Auto-install any missing packages (Flask, requests, APScheduler)
3. Start collecting threat intelligence data with geolocation
4. Launch the web dashboard in your default browser
5. Begin auto-refreshing every 15 minutes

### First Run Example
```bash
$ python threatpulse.py
ThreatPulse - Checking dependencies...
Installing Flask...
Successfully installed Flask
Installing requests...
Successfully installed requests
Installing APScheduler...
Successfully installed APScheduler

    ╔══════════════════════════════════════════════════════════════╗
    ║                         ThreatPulse                          ║
    ║              Threat Intelligence Dashboard                   ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Real-time cyber threat awareness tool                      ║
    ║  Web dashboard: http://localhost:5000                       ║
    ║  Multiple free threat intelligence sources                  ║
    ║  Auto-refresh every 15 minutes                             ║
    ║                                                            ║
    ║  Dependencies installed automatically                       ║
    ║  Geolocation and threat attribution                        ║
    ║  Browser will open automatically                           ║
    ╚══════════════════════════════════════════════════════════════╝

ThreatPulse is now running!
Opening browser automatically...
Press Ctrl+C to stop
```

## Dashboard Overview

### Live Statistics
- **Malicious IPs**: Total count with geolocation data
- **Phishing URLs**: Real-time phishing threats
- **Malware Hashes**: Recent malware samples
- **Active Sources**: Number of working threat feeds

### Live Feed Status
- **Real-time countdown**: Shows next refresh time (15:00 → 14:59 → ...)
- **Connection status**: Visual indicators (Green=Connected, Yellow=Connecting, Red=Error)
- **Source monitoring**: Individual status for each threat intelligence source

### Threat Intelligence Display

#### **Recent Malicious IPs**
- IP addresses with attack history
- **Geolocation data**: City, country, region
- **Organization**: ISP/hosting provider information
- **Threat attribution**: Potential APT groups or threat actors
- **Malware families**: Associated malware campaigns
- Source attribution and timestamps

#### **Recent Phishing URLs**
- Active phishing websites
- Source verification status
- Threat categories and malware families
- Submission timestamps

#### **Recent Malware Hashes**
- SHA256 hashes of recent malware samples
- Original filenames when available
- Malware family classification
- File types (PE, ZIP, etc.)
- First seen timestamps

## Threat Intelligence Sources

ThreatPulse aggregates data from **9 free, public sources**:

| Source | Type | Description | Focus Area |
|--------|------|-------------|------------|
| **DShield** | IPs | SANS Internet Storm Center top attacking subnets | General attacks |
| **FeodoTracker** | IPs | Feodo/Emotet botnet command & control servers | Banking trojans |
| **ThreatFox** | IPs/URLs | Recent IOCs from abuse.ch | Fresh indicators |
| **Blocklist.de** | IPs | German-based IP blacklist | Various attacks |
| **CINS Army** | IPs | Collective Intelligence Network Security | Bad actors |
| **Greensnow** | IPs | SSH/Telnet brute force attackers | Remote access |
| **PhishTank** | URLs | Community-verified phishing URLs | Phishing campaigns |
| **URLhaus** | URLs | Malicious URLs used for malware distribution | Malware delivery |
| **MalwareBazaar** | Hashes | Recent malware samples and signatures | Malware analysis |

## Geolocation & Threat Attribution

### IP Geolocation Features
- **Geographic location**: City, region, country
- **Network information**: ISP, organization, ASN
- **Coordinates**: Latitude/longitude for mapping
- **Timezone**: Local time zone information

### Threat Attribution Logic
ThreatPulse maps threat origins to known threat actors:

- **Russia**: APT28, APT29, Turla, Sandworm
- **China**: APT1, APT40, APT41, Lazarus  
- **North Korea**: Lazarus, APT38, Kimsuky
- **Iran**: APT33, APT34, APT35, MuddyWater
- **Hosting Providers**: Marked as "Compromised Infrastructure"
- **Unknown/Other**: Labeled as "Unattributed"

## Configuration

### Auto-Refresh Interval
Modify the refresh interval in the `init_scheduler()` function:

```python
scheduler.add_job(
    func=update_threat_data,
    trigger="interval",
    minutes=15,  # Change this value (1-60 minutes recommended)
    id='threat_update'
)
```

### Port Configuration
To run on a different port, modify the last line in `threatpulse.py`:

```python
app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
```

### Geolocation Service
ThreatPulse uses `ip-api.com` for free geolocation. No API key required, but has rate limits (45 requests/minute). The service can be changed in the `GeoLocationService` class.

## API Endpoints

ThreatPulse provides REST APIs for integration:

### Get All Threat Data
```bash
curl http://localhost:5000/api/threats
```

Returns complete threat data including geolocation and attribution.

### Force Refresh Data
```bash
curl -X POST http://localhost:5000/api/refresh
```

Triggers immediate data collection from all sources.

### Response Format
```json
{
  "last_update": "2025-01-20T10:30:00",
  "malicious_ips": [
    {
      "ip": "192.168.1.100",
      "source": "DShield", 
      "geolocation": {
        "country": "United States",
        "city": "New York",
        "organization": "Digital Ocean"
      },
      "threat_attribution": "Compromised Infrastructure"
    }
  ],
  "phishing_urls": [...],
  "malware_hashes": [...],
  "sources": [...]
}
```

## File Structure

```
ThreatPulse/
├── threatpulse.py      # Main application (single file solution!)
├── requirements.txt    # Dependencies (optional - auto-installed)
└── README.md          # Documentation
```

## Security Considerations

- **No Authentication Required**: All threat feeds are public
- **Read-Only Access**: ThreatPulse only consumes data, never submits
- **Data Sanitization**: All external data is validated before display
- **Local Processing**: No data is sent to external services except for geolocation
- **HTTPS Connections**: All API calls use secure connections
- **Rate Limiting**: Respects API rate limits and includes fallbacks

## Use Cases

### Security Operations Center (SOC)
- Monitor emerging threats in real-time
- Geographic threat analysis and attribution
- Quick threat landscape overview for daily briefings
- Incident response intelligence gathering

### Network Administrators  
- Identify malicious IPs targeting your network
- Understand attack origins and potential threat actors
- Stay informed about current attack campaigns
- Proactive threat blocking with geographic context

### Security Researchers
- Track malware families and campaigns
- Analyze threat actor infrastructure and attribution
- Research emerging attack vectors and TTPs
- Geographic analysis of threat distribution

### Cybersecurity Education
- Demonstrate real-world threat intelligence
- Teaching threat hunting and attribution concepts
- Security awareness training with current threats
- Hands-on experience with multiple threat feeds

## Advanced Features

### Live Status Monitoring
- Real-time connection status for each source
- Automatic retry logic for failed sources
- Visual indicators for feed health
- Countdown timer for next refresh

### Responsive Design
- **Desktop**: Three-column layout (1200px+)
- **Tablet**: Two-column layout (768px-1200px)  
- **Mobile**: Single-column layout (768px and below)
- Touch-friendly interface for mobile devices

### Performance Optimization
- Background data collection to avoid blocking UI
- Efficient data storage and retrieval
- Minimal resource usage
- Optimized for continuous operation

## Troubleshooting

### Common Issues

**Port Already in Use**
```bash
# Kill process using port 5000
lsof -ti:5000 | xargs kill -9
# Or run on different port (edit threatpulse.py)
```

**Geolocation API Rate Limiting**
- IP geolocation is limited to 45 requests/minute
- Script automatically handles rate limits
- Consider upgrading to paid geolocation service for higher volume

**Threat Source Failures**
- Some sources may be temporarily unavailable
- Dashboard shows "FAILED" status for offline sources
- Script continues collecting from available sources
- Sources automatically retry on next refresh

**Dependencies Installation Issues**
```bash
# Manual installation if auto-install fails
pip install Flask==3.0.0 requests==2.31.0 APScheduler==3.10.4
```

### Performance Tips
- Run on a server for 24/7 operation
- Monitor system resources if running continuously
- Consider log rotation for long-term operation
- Use reverse proxy (nginx) for production deployment

## Contributing

We welcome contributions! Here's how you can help:

### **Add New Threat Sources**
1. Create a new collector method in `ThreatIntelligenceCollector`
2. Add it to the `collectors` list in `collect_all_threats()`
3. Ensure proper error handling and data format
4. Add geolocation for IP-based sources

### **Improve Features**
- Enhanced threat attribution logic
- Additional geolocation providers
- Export capabilities (CSV, JSON)
- Email alerts for high-confidence threats
- Threat hunting automation

### **Code Quality**
- Follow existing code style
- Add comprehensive error handling
- Include logging for debugging
- Write documentation for new features

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

ThreatPulse is provided for **educational and security research purposes**. The threat intelligence data comes from public sources and should be validated before taking any security action. The geolocation and attribution information is based on publicly available data and should not be considered definitive. Always follow responsible disclosure and legal guidelines when using threat intelligence.

## Support & Community

### Getting Help
- Check the troubleshooting section above
- Review logs for error messages
- Ensure all dependencies are properly installed
- Verify internet connectivity for API access

### Reporting Issues
When reporting issues, please include:
- Python version (`python --version`)
- Operating system
- Error messages from logs
- Steps to reproduce the issue

### Feature Requests
We're always looking to improve ThreatPulse. Consider contributing:
- Additional threat intelligence sources
- Enhanced visualization features
- Integration capabilities
- Performance improvements

---

**ThreatPulse** - Comprehensive threat intelligence at your fingertips. Stay informed, stay secure. 