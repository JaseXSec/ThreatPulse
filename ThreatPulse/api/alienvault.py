from datetime import datetime, timedelta
from typing import Dict, List
from .client import ThreatIntelClient

class AlienVaultClient(ThreatIntelClient):
    """Client for AlienVault OTX API"""
    
    def __init__(self):
        super().__init__()
        self.base_url = "https://otx.alienvault.com/api/v1"
    
    async def get_pulses(self, days_back: int = 1) -> List[Dict]:
        """Get recent pulses from AlienVault OTX"""
        modified_since = datetime.utcnow() - timedelta(days=days_back)
        params = {
            'modified_since': modified_since.isoformat(),
            'limit': 20,
            'page': 1
        }
        
        try:
            data = await self.get(f"{self.base_url}/pulses/subscribed", params=params)
            results = []
            
            for pulse in data.get('results', []):
                results.append({
                    'type': 'pulse',
                    'name': pulse.get('name'),
                    'description': pulse.get('description'),
                    'author': pulse.get('author_name'),
                    'created': self.normalize_timestamp(pulse.get('created')),
                    'indicators': [
                        self.format_indicator(i.get('type'), i.get('indicator'))
                        for i in pulse.get('indicators', [])
                    ],
                    'tags': pulse.get('tags', []),
                    'references': pulse.get('references', []),
                    'malware_families': pulse.get('malware_families', []),
                    'industries': pulse.get('industries', []),
                    'tlp': pulse.get('tlp', 'white'),
                    'source': 'AlienVault OTX'
                })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to fetch AlienVault pulses: {str(e)}")
            return []
    
    async def get_indicators(self, type_filter: str = None) -> List[Dict]:
        """Get recent indicators from AlienVault OTX"""
        params = {
            'limit': 50,
            'page': 1
        }
        if type_filter:
            params['type'] = type_filter
            
        try:
            data = await self.get(f"{self.base_url}/indicators/export", params=params)
            results = []
            
            for indicator in data:
                results.append({
                    'type': indicator.get('type'),
                    'value': indicator.get('indicator'),
                    'description': indicator.get('description'),
                    'created': self.normalize_timestamp(indicator.get('created')),
                    'source': 'AlienVault OTX'
                })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to fetch AlienVault indicators: {str(e)}")
            return [] 