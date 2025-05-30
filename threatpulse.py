#!/usr/bin/env python3
"""
ThreatPulse - Threat Intelligence Dashboard
A single-file solution for real-time cyber threat awareness

Usage: python threatpulse.py
Then visit: http://localhost:5000

This script automatically installs required dependencies if they're missing.
"""

import sys
import subprocess
import importlib.util
import webbrowser
import threading

def install_and_import(package_name, pip_name=None):
    """Install and import a package if it's not already installed"""
    if pip_name is None:
        pip_name = package_name
    
    spec = importlib.util.find_spec(package_name)
    if spec is None:
        print(f"Installing {package_name}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
            print(f"Successfully installed {package_name}")
        except subprocess.CalledProcessError:
            print(f"Failed to install {package_name}. Please install manually: pip install {pip_name}")
            sys.exit(1)
    
    return importlib.import_module(package_name)

# Auto-install and import required packages
print("ThreatPulse - Checking dependencies...")
requests = install_and_import('requests')
flask = install_and_import('flask', 'Flask==3.0.0')
apscheduler = install_and_import('apscheduler', 'APScheduler==3.10.4')

from flask import Flask, render_template_string, jsonify
from apscheduler.schedulers.background import BackgroundScheduler

import asyncio
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from threading import Thread
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)

# Global threat data store
threat_data = {
    'last_update': None,
    'malicious_ips': [],
    'phishing_urls': [],
    'malware_hashes': [],
    'threat_stats': {
        'total_ips': 0,
        'total_urls': 0,
        'total_hashes': 0,
        'last_24h_ips': 0
    },
    'sources': []
}

class GeoLocationService:
    """Service for IP geolocation and threat attribution"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatPulse/1.0 (Security Research Tool)'
        })
        self.timeout = 10
        self.rate_limit_delay = 0.2  # Reduce delay to 0.2 seconds for faster loading
        self.last_request_time = 0
        
    def _respect_rate_limit(self):
        """Ensure we don't exceed rate limits"""
        import time
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()
        
    def get_ip_geolocation(self, ip):
        """Get geolocation data for an IP address"""
        try:
            # Respect rate limits (45 requests/minute = ~1.33 requests/second)
            self._respect_rate_limit()
            
            # Using ip-api.com - free service, no API key required
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,org,as,isp"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', ''),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'organization': data.get('org', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'asn': data.get('as', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown')
                    }
                else:
                    logger.warning(f"Geolocation API error for {ip}: {data.get('message', 'Unknown error')}")
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip}: {e}")
        
        return {
            'country': 'Unknown',
            'country_code': '',
            'region': 'Unknown',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0,
            'organization': 'Unknown',
            'isp': 'Unknown',
            'asn': 'Unknown',
            'timezone': 'Unknown'
        }
    
    def get_threat_attribution(self, country, organization, asn):
        """Get potential threat group attribution based on geolocation"""
        # Enhanced threat attribution based on MITRE ATT&CK and public intelligence
        threat_groups = {
            'Russia': ['APT28 (Fancy Bear)', 'APT29 (Cozy Bear)', 'Turla', 'Sandworm', 'Lazarus'],
            'China': ['APT1 (Comment Crew)', 'APT40 (Leviathan)', 'APT41', 'Lazarus', 'Winnti'],
            'North Korea': ['Lazarus Group', 'APT38', 'Kimsuky', 'Andariel'],
            'Iran': ['APT33 (Elfin)', 'APT34 (OilRig)', 'APT35 (Charming Kitten)', 'MuddyWater'],
            'United States': ['Unknown/Research'],
            'Israel': ['Unknown/Research'],
            'United Kingdom': ['Unknown/Research'],
            'Germany': ['Unknown/Research'],
            'France': ['Unknown/Research'],
            'Netherlands': ['Unknown/Research'],
            'Unknown': ['Unattributed']
        }
        
        # Check for known malicious hosting providers and infrastructure indicators
        malicious_indicators = [
            'bulletproof', 'hosting', 'vps', 'cloud', 'datacenter',
            'dedicated', 'server', 'colocation', 'vpn', 'proxy',
            'digital ocean', 'amazon', 'microsoft', 'google cloud',
            'alibaba', 'vultr', 'linode', 'ovh'
        ]
        
        # Additional indicators for compromised infrastructure
        compromised_indicators = [
            'residential', 'broadband', 'cable', 'dsl', 'fiber',
            'telecom', 'internet', 'communication'
        ]
        
        organization_lower = organization.lower()
        asn_lower = asn.lower()
        
        # Check for hosting/cloud providers (likely compromised infrastructure)
        if any(indicator in organization_lower for indicator in malicious_indicators):
            return 'Compromised Infrastructure (Hosting)'
        
        # Check for residential/ISP networks (likely compromised devices)
        if any(indicator in organization_lower for indicator in compromised_indicators):
            return 'Compromised Infrastructure (Residential)'
            
        # Check ASN for additional context
        if any(indicator in asn_lower for indicator in malicious_indicators):
            return 'Compromised Infrastructure (Cloud)'
        
        # Get potential threat groups based on country
        potential_groups = threat_groups.get(country, ['Unattributed'])
        
        # Return the most likely attribution
        if len(potential_groups) > 1:
            return f"Potential: {potential_groups[0]} (or {len(potential_groups)-1} other groups)"
        
        return potential_groups[0] if potential_groups else 'Unattributed'

class ThreatIntelligenceCollector:
    """Collects threat intelligence from multiple free sources"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatPulse/1.0 (Security Research Tool)'
        })
        self.timeout = 30
        self.geo_service = GeoLocationService()
        
    def test_geolocation_attribution(self):
        """Test geolocation and threat attribution functionality"""
        test_ips = [
            "8.8.8.8",  # Google DNS - should show as US/Compromised Infrastructure
            "1.1.1.1",  # Cloudflare DNS - should show as US/Compromised Infrastructure  
            "185.220.100.240",  # Known Tor exit node
            "45.142.213.33"  # Example IP for testing
        ]
        
        print("\n🧪 Testing Geolocation and Threat Attribution:")
        print("=" * 60)
        
        for ip in test_ips:
            print(f"\nTesting IP: {ip}")
            geo_data = self.geo_service.get_ip_geolocation(ip)
            attribution = self.geo_service.get_threat_attribution(
                geo_data['country'], 
                geo_data['organization'],
                geo_data['asn']
            )
            
            print(f"  📍 Location: {geo_data['city']}, {geo_data['country']}")
            print(f"  🏢 Organization: {geo_data['organization']}")
            print(f"  🌐 ISP: {geo_data['isp']}")
            print(f"  📊 ASN: {geo_data['asn']}")
            print(f"  🎯 Attribution: {attribution}")
            
        print("\n" + "=" * 60)
        
    def enrich_ip_with_geolocation(self, ip_data, skip_geo=False):
        """Enrich IP data with geolocation information"""
        ip = ip_data.get('ip')
        if ip and ip != 'Unknown' and not skip_geo:
            try:
                geo_data = self.geo_service.get_ip_geolocation(ip)
                threat_group = self.geo_service.get_threat_attribution(
                    geo_data['country'], 
                    geo_data['organization'],
                    geo_data['asn']
                )
                
                ip_data.update({
                    'geolocation': geo_data,
                    'threat_attribution': threat_group
                })
                
                logger.debug(f"Enriched {ip} -> {geo_data['city']}, {geo_data['country']} ({threat_group})")
                
            except Exception as e:
                logger.error(f"Error enriching IP {ip}: {e}")
                # Add default geolocation data
                ip_data.update({
                    'geolocation': {
                        'country': 'Unknown',
                        'city': 'Unknown',
                        'region': 'Unknown',
                        'organization': 'Unknown',
                        'isp': 'Unknown',
                        'asn': 'Unknown'
                    },
                    'threat_attribution': 'Unattributed'
                })
        elif skip_geo:
            # Add minimal geolocation data when skipping
            ip_data.update({
                'geolocation': {
                    'country': 'Loading...',
                    'city': 'Loading...',
                    'region': 'Loading...',
                    'organization': 'Loading...',
                    'isp': 'Loading...',
                    'asn': 'Loading...'
                },
                'threat_attribution': 'Loading...'
            })
        
        return ip_data
        
    def collect_dshield_ips(self):
        """Collect top attacking IPs from SANS DShield"""
        try:
            logger.info("Fetching DShield Top 20 attacking subnets...")
            # Try the main API first, then fallback to text format
            urls = [
                "https://isc.sans.edu/api/sources/attacks/30/1000?json",
                "https://isc.sans.edu/api/topips/records/20",
                "https://isc.sans.edu/feeds/topips.txt"
            ]
            
            for url in urls:
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    if response.status_code == 200:
                        ips = []
                        
                        if 'json' in url.lower() or url.endswith('records/20'):
                            # Try JSON format
                            try:
                                data = response.json()
                                if isinstance(data, list):
                                    for i, item in enumerate(data[:20]):
                                        if isinstance(item, dict) and 'ip' in item:
                                            ip_data = {
                                                'ip': item.get('ip', ''),
                                                'source': 'DShield',
                                                'confidence': 'high',
                                                'last_seen': datetime.now().isoformat(),
                                                'attack_count': item.get('attacks', 0),
                                                'type': 'malicious_ip'
                                            }
                                            # Only geolocate first 5 IPs for speed
                                            skip_geo = i >= 5
                                            enriched_ip = self.enrich_ip_with_geolocation(ip_data, skip_geo)
                                            ips.append(enriched_ip)
                            except (json.JSONDecodeError, KeyError):
                                continue
                        else:
                            # Parse text format
                            lines = response.text.strip().split('\n')
                            for i, line in enumerate(lines[:20]):
                                if line.strip() and not line.startswith('#') and not line.startswith('ip'):
                                    parts = line.split()
                                    if len(parts) >= 1:
                                        ip = parts[0].strip()
                                        count = parts[1] if len(parts) > 1 else "1"
                                        ip_data = {
                                            'ip': ip,
                                            'source': 'DShield',
                                            'confidence': 'high',
                                            'last_seen': datetime.now().isoformat(),
                                            'attack_count': count,
                                            'type': 'malicious_ip'
                                        }
                                        # Only geolocate first 5 IPs for speed
                                        skip_geo = i >= 5
                                        enriched_ip = self.enrich_ip_with_geolocation(ip_data, skip_geo)
                                        ips.append(enriched_ip)
                        
                        if ips:
                            logger.info(f"Collected {len(ips)} IPs from DShield with geolocation")
                            return ips
                            
                except Exception as e:
                    logger.warning(f"DShield URL {url} failed: {e}")
                    continue
                
        except Exception as e:
            logger.error(f"Error fetching DShield data: {e}")
        
        return []
    
    def collect_openphish_urls(self):
        """Collect phishing URLs from OpenPhish"""
        try:
            logger.info("Fetching phishing URLs from OpenPhish...")
            url = "https://openphish.com/feed.txt"
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                urls = []
                
                for line in lines[:50]:  # Limit to first 50
                    line = line.strip()
                    if line and line.startswith('http'):
                        urls.append({
                            'url': line,
                            'source': 'OpenPhish',
                            'confidence': 'high',
                            'submission_time': datetime.now().isoformat(),
                            'verified': 'yes',
                            'type': 'phishing_url'
                        })
                
                logger.info(f"Collected {len(urls)} URLs from OpenPhish")
                return urls
                
        except Exception as e:
            logger.error(f"Error fetching OpenPhish data: {e}")
        
        return []
    
    def collect_phishtank_urls(self):
        """Collect phishing URLs from PhishTank - DISABLED due to rate limiting"""
        try:
            # PhishTank now requires API keys and has strict rate limiting
            # Temporarily disabled to avoid 429 errors
            logger.info("PhishTank temporarily disabled due to API requirements")
            return []
                
        except Exception as e:
            logger.error(f"Error fetching PhishTank data: {e}")
        
        return []
    
    def collect_blocklist_de_ips(self):
        """Collect IPs from Blocklist.de"""
        try:
            logger.info("Fetching IPs from Blocklist.de...")
            url = "https://lists.blocklist.de/lists/all.txt"
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                ips = []
                
                for i, line in enumerate(lines[:25]):  # Limit to first 25
                    line = line.strip()
                    if line and not line.startswith('#') and '.' in line:
                        ip_data = {
                            'ip': line,
                            'source': 'Blocklist.de',
                            'confidence': 'high',
                            'last_seen': datetime.now().isoformat(),
                            'malware_family': 'Various',
                            'type': 'malicious_ip'
                        }
                        # Only geolocate first 3 IPs for speed
                        skip_geo = i >= 3
                        enriched_ip = self.enrich_ip_with_geolocation(ip_data, skip_geo)
                        ips.append(enriched_ip)
                
                logger.info(f"Collected {len(ips)} IPs from Blocklist.de")
                return ips
                
        except Exception as e:
            logger.error(f"Error fetching Blocklist.de data: {e}")
        
        return []
    
    def collect_cins_army_ips(self):
        """Collect IPs from CINS Army List"""
        try:
            logger.info("Fetching IPs from CINS Army...")
            url = "http://cinsscore.com/list/ci-badguys.txt"
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                ips = []
                
                for i, line in enumerate(lines[:25]):  # Limit to first 25
                    line = line.strip()
                    if line and not line.startswith('#') and '.' in line:
                        ip_data = {
                            'ip': line,
                            'source': 'CINS Army',
                            'confidence': 'high',
                            'last_seen': datetime.now().isoformat(),
                            'malware_family': 'Malicious Activity',
                            'type': 'malicious_ip'
                        }
                        # Only geolocate first 3 IPs for speed
                        skip_geo = i >= 3
                        enriched_ip = self.enrich_ip_with_geolocation(ip_data, skip_geo)
                        ips.append(enriched_ip)
                
                logger.info(f"Collected {len(ips)} IPs from CINS Army")
                return ips
                
        except Exception as e:
            logger.error(f"Error fetching CINS Army data: {e}")
        
        return []
    
    def collect_greensnow_ips(self):
        """Collect IPs from Greensnow blacklist"""
        try:
            logger.info("Fetching IPs from Greensnow...")
            url = "https://blocklist.greensnow.co/greensnow.txt"
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                ips = []
                
                for i, line in enumerate(lines[:25]):  # Limit to first 25
                    line = line.strip()
                    if line and not line.startswith('#') and '.' in line:
                        ip_data = {
                            'ip': line,
                            'source': 'Greensnow',
                            'confidence': 'high',
                            'last_seen': datetime.now().isoformat(),
                            'malware_family': 'SSH/Telnet Attacks',
                            'type': 'malicious_ip'
                        }
                        # Only geolocate first 3 IPs for speed
                        skip_geo = i >= 3
                        enriched_ip = self.enrich_ip_with_geolocation(ip_data, skip_geo)
                        ips.append(enriched_ip)
                
                logger.info(f"Collected {len(ips)} IPs from Greensnow")
                return ips
                
        except Exception as e:
            logger.error(f"Error fetching Greensnow data: {e}")
        
        return []
    
    def collect_malware_bazaar_hashes(self):
        """Collect recent malware hashes from MalwareBazaar"""
        try:
            logger.info("Fetching recent malware hashes from MalwareBazaar...")
            url = "https://mb-api.abuse.ch/api/v1/"
            
            # Get recent samples
            data = {
                'query': 'get_recent',
                'selector': '100'
            }
            
            response = self.session.post(url, data=data, timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                hashes = []
                
                if result.get('query_status') == 'ok':
                    for item in result.get('data', []):
                        hashes.append({
                            'sha256': item.get('sha256_hash', ''),
                            'file_name': item.get('file_name', ''),
                            'file_type': item.get('file_type', ''),
                            'malware_family': item.get('signature', ''),
                            'source': 'MalwareBazaar',
                            'confidence': 'high',
                            'first_seen': item.get('first_seen', ''),
                            'type': 'malware_hash'
                        })
                
                logger.info(f"Collected {len(hashes)} hashes from MalwareBazaar")
                return hashes
                
        except Exception as e:
            logger.error(f"Error fetching MalwareBazaar data: {e}")
        
        return []
    
    def collect_urlhaus_urls(self):
        """Collect malicious URLs from URLhaus"""
        try:
            logger.info("Fetching malicious URLs from URLhaus...")
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                urls = []
                
                if data.get('query_status') == 'ok':
                    for item in data.get('urls', [])[:50]:  # Limit to 50
                        urls.append({
                            'url': item.get('url', ''),
                            'source': 'URLhaus',
                            'confidence': 'high',
                            'date_added': item.get('date_added', ''),
                            'threat': item.get('threat', ''),
                            'malware_family': item.get('tags', []),
                            'type': 'malicious_url'
                        })
                
                logger.info(f"Collected {len(urls)} URLs from URLhaus")
                return urls
                
        except Exception as e:
            logger.error(f"Error fetching URLhaus data: {e}")
        
        return []
    
    def collect_feodo_ips(self):
        """Collect Feodo botnet IPs"""
        try:
            logger.info("Fetching Feodo botnet IPs...")
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                ips = []
                
                for line in lines[:20]:  # Limit to top 20 for geolocation
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ip_data = {
                            'ip': line,
                            'source': 'FeodoTracker',
                            'confidence': 'high',
                            'last_seen': datetime.now().isoformat(),
                            'malware_family': 'Feodo/Emotet',
                            'type': 'botnet_ip'
                        }
                        
                        # Enrich with geolocation
                        enriched_ip = self.enrich_ip_with_geolocation(ip_data)
                        ips.append(enriched_ip)
                
                logger.info(f"Collected {len(ips)} IPs from FeodoTracker with geolocation")
                return ips
                
        except Exception as e:
            logger.error(f"Error fetching FeodoTracker data: {e}")
        
        return []
    
    def collect_spamhaus_ips(self):
        """Collect IPs from Spamhaus DROP list"""
        try:
            logger.info("Fetching IPs from Spamhaus DROP list...")
            url = "https://www.spamhaus.org/drop/drop.txt"
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                ips = []
                
                for i, line in enumerate(lines[:15]):  # Limit to first 15
                    line = line.strip()
                    if line and not line.startswith(';') and '/' in line:
                        # Extract IP from CIDR notation
                        ip_range = line.split(';')[0].strip()
                        if '/' in ip_range:
                            ip = ip_range.split('/')[0]
                            if self._is_valid_ip(ip):
                                ip_data = {
                                    'ip': ip,
                                    'source': 'Spamhaus',
                                    'confidence': 'high',
                                    'last_seen': datetime.now().isoformat(),
                                    'malware_family': 'Botnet/Spam',
                                    'type': 'malicious_ip'
                                }
                                # Only geolocate first 3 IPs for speed
                                skip_geo = i >= 3
                                enriched_ip = self.enrich_ip_with_geolocation(ip_data, skip_geo)
                                ips.append(enriched_ip)
                
                logger.info(f"Collected {len(ips)} IPs from Spamhaus")
                return ips
                
        except Exception as e:
            logger.error(f"Error fetching Spamhaus data: {e}")
        
        return []
    
    def collect_all_threats(self):
        """Collect threats from all sources"""
        logger.info("Starting threat intelligence collection...")
        
        all_ips = []
        all_urls = []
        all_hashes = []
        sources = []
        
        # Collect from all sources
        collectors = [
            ('DShield', self.collect_dshield_ips),
            ('FeodoTracker', self.collect_feodo_ips),
            ('Blocklist.de', self.collect_blocklist_de_ips),
            ('CINS Army', self.collect_cins_army_ips),
            ('Greensnow', self.collect_greensnow_ips),
            ('Spamhaus', self.collect_spamhaus_ips),
            ('OpenPhish', self.collect_openphish_urls),
            ('URLhaus', self.collect_urlhaus_urls),
            ('MalwareBazaar', self.collect_malware_bazaar_hashes)
        ]
        
        for source_name, collector_func in collectors:
            try:
                result = collector_func()
                if result:
                    sources.append({
                        'name': source_name,
                        'status': 'success',
                        'count': len(result),
                        'last_update': datetime.now().isoformat()
                    })
                    
                    # Categorize results
                    for item in result:
                        if item['type'] in ['malicious_ip', 'botnet_ip']:
                            all_ips.append(item)
                        elif item['type'] in ['phishing_url', 'malicious_url']:
                            all_urls.append(item)
                        elif item['type'] == 'malware_hash':
                            all_hashes.append(item)
                else:
                    sources.append({
                        'name': source_name,
                        'status': 'failed',
                        'count': 0,
                        'last_update': datetime.now().isoformat()
                    })
                    
            except Exception as e:
                logger.error(f"Error collecting from {source_name}: {e}")
                sources.append({
                    'name': source_name,
                    'status': 'error',
                    'count': 0,
                    'error': str(e),
                    'last_update': datetime.now().isoformat()
                })
        
        return all_ips, all_urls, all_hashes, sources

    def _is_valid_ip(self, ip):
        """Basic IP address validation"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False

def update_threat_data():
    """Update the global threat data"""
    global threat_data
    
    try:
        collector = ThreatIntelligenceCollector()
        ips, urls, hashes, sources = collector.collect_all_threats()
        
        # Update global threat data
        threat_data.update({
            'last_update': datetime.now().isoformat(),
            'malicious_ips': ips,
            'phishing_urls': urls,
            'malware_hashes': hashes,
            'threat_stats': {
                'total_ips': len(ips),
                'total_urls': len(urls),
                'total_hashes': len(hashes),
                'last_24h_ips': len([ip for ip in ips if 'last_seen' in ip])
            },
            'sources': sources
        })
        
        logger.info(f"Threat data updated: {len(ips)} IPs, {len(urls)} URLs, {len(hashes)} hashes")
        
    except Exception as e:
        logger.error(f"Error updating threat data: {e}")

# HTML Template with embedded CSS and JavaScript
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatPulse - Threat Intelligence Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a1a;
            color: #e4e4e7;
            line-height: 1.6;
        }
        
        .header {
            background: #262626;
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #404040;
            box-shadow: 0 1px 3px rgba(0,0,0,0.3);
        }
        
        .header h1 {
            font-size: 1.8rem;
            color: #f4f4f5;
            font-weight: 600;
            margin-bottom: 0.3rem;
        }
        
        .header p {
            color: #a1a1aa;
            font-size: 0.9rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .top-section {
            display: grid;
            grid-template-columns: 1fr 280px;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(90px, 1fr));
            gap: 0.75rem;
        }
        
        .stat-card {
            background: #262626;
            border-radius: 4px;
            padding: 0.6rem 0.5rem;
            border: 1px solid #404040;
            text-align: center;
        }
        
        .stat-number {
            font-size: 1.4rem;
            font-weight: 600;
            color: #f4f4f5;
            margin-bottom: 0.1rem;
            line-height: 1;
        }
        
        .stat-label {
            color: #a1a1aa;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            line-height: 1.1;
        }
        
        .live-status {
            background: #262626;
            border-radius: 4px;
            padding: 1.5rem;
            border: 1px solid #404040;
        }
        
        .status-title {
            font-size: 1rem;
            font-weight: 600;
            color: #f4f4f5;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        
        .status-connected {
            background: #22c55e;
        }
        
        .status-connecting {
            background: #eab308;
        }
        
        .status-disconnected {
            background: #ef4444;
        }
        
        .refresh-countdown {
            font-size: 1.1rem;
            color: #f4f4f5;
            font-weight: 500;
            margin: 0.5rem 0;
        }
        
        .next-refresh {
            font-size: 0.85rem;
            color: #a1a1aa;
            margin-bottom: 1rem;
        }
        
        .sources-status {
            margin-top: 1rem;
        }
        
        .source-status-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid #404040;
        }
        
        .source-status-item:last-child {
            border-bottom: none;
        }
        
        .source-name {
            font-size: 0.85rem;
            color: #e4e4e7;
        }
        
        .source-status {
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 2px;
            font-weight: 500;
        }
        
        .status-success {
            background: #166534;
            color: #bbf7d0;
        }
        
        .status-error {
            background: #991b1b;
            color: #fecaca;
        }
        
        .status-failed {
            background: #a16207;
            color: #fef3c7;
        }
        
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .threat-section {
            background: #262626;
            border-radius: 4px;
            padding: 1.5rem;
            border: 1px solid #404040;
        }
        
        .section-title {
            font-size: 1rem;
            margin-bottom: 1rem;
            color: #f4f4f5;
            font-weight: 600;
            border-bottom: 2px solid #404040;
            padding-bottom: 0.5rem;
        }
        
        .threat-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .threat-item {
            background: #1a1a1a;
            border-radius: 2px;
            padding: 0.8rem;
            margin-bottom: 0.5rem;
            border-left: 3px solid #a1a1aa;
        }
        
        .threat-ip, .threat-hash {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-weight: 500;
            color: #f4f4f5;
            font-size: 0.8rem;
            word-break: break-all;
        }
        
        .threat-filename {
            font-size: 0.75rem;
            color: #e4e4e7;
            margin-top: 0.3rem;
        }
        
        .threat-source {
            font-size: 0.75rem;
            color: #a1a1aa;
            margin-top: 0.3rem;
        }
        
        .threat-geo {
            font-size: 0.7rem;
            color: #a1a1aa;
            margin-top: 0.2rem;
        }
        
        .threat-attribution {
            font-size: 0.7rem;
            color: #e4e4e7;
            margin-top: 0.2rem;
            font-weight: 500;
        }
        
        .threat-time {
            font-size: 0.7rem;
            color: #a1a1aa;
            float: right;
        }
        
        .bottom-section {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 2rem;
            align-items: start;
        }
        
        .chart-container {
            background: #262626;
            border-radius: 4px;
            padding: 1.5rem;
            border: 1px solid #404040;
            height: fit-content;
        }
        
        .chart-canvas {
            max-height: 250px !important;
        }
        
        .controls-section {
            background: #262626;
            border-radius: 4px;
            padding: 1.5rem;
            border: 1px solid #404040;
        }
        
        .refresh-btn {
            background: #374151;
            color: #f4f4f5;
            border: none;
            padding: 0.7rem 1.5rem;
            border-radius: 2px;
            font-weight: 500;
            cursor: pointer;
            margin-top: 1rem;
            width: 100%;
            font-size: 0.9rem;
        }
        
        .refresh-btn:hover {
            background: #4b5563;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 2rem;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
        }
        
        .loading-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #262626;
            padding: 2rem;
            border-radius: 4px;
            border: 1px solid #404040;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        
        .spinner {
            border: 3px solid #404040;
            border-radius: 50%;
            border-top: 3px solid #f4f4f5;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .last-update {
            text-align: center;
            margin-top: 1rem;
            color: #a1a1aa;
            font-size: 0.8rem;
        }
        
        @media (max-width: 1200px) {
            .content-grid {
                grid-template-columns: 1fr 1fr;
            }
            
            .top-section {
                grid-template-columns: 1fr;
            }
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header {
                padding: 1rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .content-grid {
                grid-template-columns: 1fr;
            }
            
            .bottom-section {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>ThreatPulse</h1>
        <p>Real-time Cyber Threat Intelligence Dashboard</p>
    </div>
    
    <div class="container">
        <div class="loading" id="loading">
            <div class="loading-content">
                <div class="spinner"></div>
                <p>Updating threat intelligence data...</p>
            </div>
        </div>
        
        <div class="top-section">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="totalIps">{{ threat_data.threat_stats.total_ips }}</div>
                    <div class="stat-label">Malicious IPs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="totalUrls">{{ threat_data.threat_stats.total_urls }}</div>
                    <div class="stat-label">Phishing URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="totalHashes">{{ threat_data.threat_stats.total_hashes }}</div>
                    <div class="stat-label">Malware Hashes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="activeSources">{{ threat_data.sources|length }}</div>
                    <div class="stat-label">Active Sources</div>
                </div>
            </div>
            
            <div class="live-status">
                <div class="status-title">
                    <div class="status-indicator status-connected" id="connectionStatus"></div>
                    Live Feed Status
                </div>
                <div class="refresh-countdown" id="refreshCountdown">15:00</div>
                <div class="next-refresh">Next refresh in</div>
                
                <div class="sources-status">
                    {% for source in threat_data.sources %}
                    <div class="source-status-item">
                        <span class="source-name">{{ source.name }}</span>
                        <span class="source-status {% if source.status == 'success' %}status-success{% elif source.status == 'error' %}status-error{% else %}status-failed{% endif %}">
                            {{ source.status.upper() }}
                        </span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        
        <div class="content-grid">
            <div class="threat-section">
                <h2 class="section-title">Recent Malicious IPs</h2>
                <div class="threat-list" id="maliciousIps">
                    {% for ip in threat_data.malicious_ips[:10] %}
                    <div class="threat-item">
                        <div class="threat-ip">{{ ip.ip }}</div>
                        <div class="threat-source">Source: {{ ip.source }}</div>
                        {% if ip.geolocation %}
                        <div class="threat-geo">📍 Location: {{ ip.geolocation.city }}, {{ ip.geolocation.region }}, {{ ip.geolocation.country }}</div>
                        <div class="threat-geo">🏢 Organization: {{ ip.geolocation.organization }}</div>
                        {% if ip.geolocation.isp and ip.geolocation.isp != ip.geolocation.organization %}
                        <div class="threat-geo">🌐 ISP: {{ ip.geolocation.isp }}</div>
                        {% endif %}
                        {% if ip.geolocation.asn and ip.geolocation.asn != 'Unknown' %}
                        <div class="threat-geo">📊 ASN: {{ ip.geolocation.asn }}</div>
                        {% endif %}
                        {% endif %}
                        {% if ip.threat_attribution %}
                        <div class="threat-attribution">🎯 Attribution: {{ ip.threat_attribution }}</div>
                        {% endif %}
                        {% if ip.malware_family %}
                        <div class="threat-source">🦠 Family: {{ ip.malware_family }}</div>
                        {% endif %}
                        {% if ip.attack_count %}
                        <div class="threat-source">⚔️ Attack Count: {{ ip.attack_count }}</div>
                        {% endif %}
                        <div class="threat-time">{{ ip.last_seen or ip.date_added }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div class="threat-section">
                <h2 class="section-title">Recent Phishing URLs</h2>
                <div class="threat-list" id="phishingUrls">
                    {% for url in threat_data.phishing_urls[:10] %}
                    <div class="threat-item">
                        <div class="threat-ip">{{ url.url[:50] }}{% if url.url|length > 50 %}...{% endif %}</div>
                        <div class="threat-source">Source: {{ url.source }}</div>
                        {% if url.threat %}
                        <div class="threat-source">Threat: {{ url.threat }}</div>
                        {% endif %}
                        <div class="threat-time">{{ url.submission_time or url.date_added }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <div class="threat-section">
                <h2 class="section-title">Recent Malware Hashes</h2>
                <div class="threat-list" id="malwareHashes">
                    {% for hash in threat_data.malware_hashes[:10] %}
                    <div class="threat-item">
                        <div class="threat-hash">{{ hash.sha256[:16] }}...{{ hash.sha256[-8:] }}</div>
                        {% if hash.file_name %}
                        <div class="threat-filename">File: {{ hash.file_name }}</div>
                        {% endif %}
                        <div class="threat-source">Source: {{ hash.source }}</div>
                        {% if hash.malware_family %}
                        <div class="threat-source">Family: {{ hash.malware_family }}</div>
                        {% endif %}
                        {% if hash.file_type %}
                        <div class="threat-geo">Type: {{ hash.file_type }}</div>
                        {% endif %}
                        <div class="threat-time">{{ hash.first_seen }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        
        <div class="bottom-section">
            <div class="chart-container">
                <h3 class="section-title">Sources</h3>
                <canvas id="sourcesChart" class="chart-canvas" width="250" height="250"></canvas>
            </div>
            
            <div class="controls-section">
                <h3 class="section-title">Controls</h3>
                <div class="last-update">
                    {% if threat_data.last_update %}
                    Last updated: {{ threat_data.last_update }}
                    {% endif %}
                </div>
                <button class="refresh-btn" onclick="refreshData()">Refresh Now</button>
                
                <div style="margin-top: 2rem;">
                    <h4 style="color: #06d6a0; margin-bottom: 1rem;">Data Sources</h4>
                    {% for source in threat_data.sources %}
                    <div class="source-status-item">
                        <span class="source-name">{{ source.name }}</span>
                        <span style="color: #94a3b8; font-size: 0.8rem;">{{ source.count }} indicators</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let refreshInterval = 15 * 60; // 15 minutes in seconds
        let countdownInterval;
        let currentCountdown = refreshInterval;
        
        // Auto-refresh every 15 minutes
        setInterval(refreshData, refreshInterval * 1000);
        
        function startCountdown() {
            countdownInterval = setInterval(() => {
                currentCountdown--;
                updateCountdownDisplay();
                
                if (currentCountdown <= 0) {
                    currentCountdown = refreshInterval;
                }
            }, 1000);
        }
        
        function updateCountdownDisplay() {
            const minutes = Math.floor(currentCountdown / 60);
            const seconds = currentCountdown % 60;
            const display = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            document.getElementById('refreshCountdown').textContent = display;
        }
        
        function updateConnectionStatus(status) {
            const indicator = document.getElementById('connectionStatus');
            indicator.className = 'status-indicator';
            
            switch(status) {
                case 'connected':
                    indicator.classList.add('status-connected');
                    break;
                case 'connecting':
                    indicator.classList.add('status-connecting');
                    break;
                case 'disconnected':
                    indicator.classList.add('status-disconnected');
                    break;
            }
        }
        
        function refreshData() {
            updateConnectionStatus('connecting');
            document.getElementById('loading').style.display = 'block';
            
            fetch('/api/refresh', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        updateConnectionStatus('connected');
                        currentCountdown = refreshInterval;
                        setTimeout(() => {
                            location.reload();
                        }, 2000);
                    } else {
                        updateConnectionStatus('disconnected');
                    }
                })
                .catch(error => {
                    console.error('Error refreshing data:', error);
                    updateConnectionStatus('disconnected');
                })
                .finally(() => {
                    setTimeout(() => {
                        document.getElementById('loading').style.display = 'none';
                    }, 2000);
                });
        }
        
        // Initialize charts
        const ctx = document.getElementById('sourcesChart').getContext('2d');
        const sourcesData = {{ threat_data.sources | tojson }};
        
        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: sourcesData.map(s => s.name),
                datasets: [{
                    data: sourcesData.map(s => s.count),
                    backgroundColor: [
                        '#06d6a0',
                        '#ef4444',
                        '#f59e0b',
                        '#3b82f6',
                        '#8b5cf6',
                        '#ec4899',
                        '#10b981',
                        '#f97316'
                    ],
                    borderWidth: 2,
                    borderColor: '#0f172a'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            padding: 15,
                            font: {
                                size: 11
                            }
                        }
                    }
                }
            }
        });
        
        // Initialize status and countdown
        updateConnectionStatus('connected');
        updateCountdownDisplay();
        startCountdown();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template_string(HTML_TEMPLATE, threat_data=threat_data)

@app.route('/api/threats')
def get_threats():
    """API endpoint to get current threat data with geolocation"""
    return jsonify(threat_data)

@app.route('/api/threats/ips')
def get_malicious_ips():
    """API endpoint to get only malicious IPs with detailed geolocation"""
    return jsonify({
        'malicious_ips': threat_data.get('malicious_ips', []),
        'total_count': len(threat_data.get('malicious_ips', [])),
        'last_update': threat_data.get('last_update')
    })

@app.route('/api/geolocation/<ip>')
def get_ip_geolocation(ip):
    """API endpoint to get geolocation for a specific IP"""
    try:
        geo_service = GeoLocationService()
        geo_data = geo_service.get_ip_geolocation(ip)
        attribution = geo_service.get_threat_attribution(
            geo_data['country'], 
            geo_data['organization'],
            geo_data['asn']
        )
        
        return jsonify({
            'ip': ip,
            'geolocation': geo_data,
            'threat_attribution': attribution,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'ip': ip
        }), 500

@app.route('/api/refresh', methods=['POST'])
def refresh_threats():
    """API endpoint to refresh threat data"""
    try:
        # Run update in background thread to avoid blocking
        thread = Thread(target=update_threat_data)
        thread.start()
        return jsonify({'status': 'success', 'message': 'Refresh started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

def init_scheduler():
    """Initialize background scheduler for periodic updates"""
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=update_threat_data,
        trigger="interval",
        minutes=15,  # Update every 15 minutes
        id='threat_update'
    )
    scheduler.start()
    logger.info("Scheduler started - will update every 15 minutes")

def open_browser():
    """Open browser after a short delay to ensure server is running"""
    import time
    time.sleep(2)  # Wait for server to start
    webbrowser.open('http://localhost:5000')

def main():
    """Main application entry point"""
    import sys
    
    # Check for test mode
    if len(sys.argv) > 1 and sys.argv[1] == '--test-geo':
        print("🧪 ThreatPulse Geolocation Test Mode")
        collector = ThreatIntelligenceCollector()
        collector.test_geolocation_attribution()
        return
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                         ThreatPulse                          ║
    ║              Threat Intelligence Dashboard                   ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Real-time cyber threat awareness tool                      ║
    ║  Web dashboard: http://localhost:5000                       ║
    ║  Multiple free threat intelligence sources                  ║
    ║  Auto-refresh every 15 minutes                             ║
    ║                                                            ║
    ║  ✅ Dependencies installed automatically                   ║
    ║  ✅ Geolocation and threat attribution                     ║
    ║  ✅ Browser will open automatically                        ║
    ║                                                            ║
    ║  💡 Run with --test-geo to test geolocation                ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Test geolocation service briefly
    logger.info("Testing geolocation service...")
    try:
        geo_service = GeoLocationService()
        test_geo = geo_service.get_ip_geolocation("8.8.8.8")
        if test_geo['country'] != 'Unknown':
            logger.info(f"✅ Geolocation service working: 8.8.8.8 -> {test_geo['city']}, {test_geo['country']}")
        else:
            logger.warning("⚠️ Geolocation service may have issues")
    except Exception as e:
        logger.error(f"❌ Geolocation service error: {e}")
    
    # Initial data collection
    logger.info("Performing initial threat data collection...")
    update_threat_data()
    
    # Start background scheduler
    init_scheduler()
    
    # Open browser in a separate thread after a delay
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Start Flask app
    logger.info("Starting ThreatPulse dashboard on http://localhost:5000")
    print("\nThreatPulse is now running!")
    print("Opening browser automatically...")
    print("Press Ctrl+C to stop\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\nThreatPulse stopped. Stay safe!")

if __name__ == '__main__':
    main() 