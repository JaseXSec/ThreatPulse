import aiohttp
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class ThreatIntelClient:
    """Base class for threat intelligence API clients"""
    
    def __init__(self):
        self.session = None
        self.headers = {
            'User-Agent': 'ThreatPulse/1.0',
            'Accept': 'application/json'
        }
    
    async def init_session(self):
        """Initialize aiohttp session"""
        if not self.session:
            self.session = aiohttp.ClientSession(headers=self.headers)
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def get(self, url: str, params: Optional[Dict] = None) -> Dict:
        """Make GET request to API endpoint"""
        try:
            await self.init_session()
            async with self.session.get(url, params=params) as response:
                response.raise_for_status()
                return await response.json()
        except aiohttp.ClientError as e:
            logger.error(f"API request failed: {str(e)}")
            return {}
    
    def normalize_timestamp(self, timestamp: str) -> datetime:
        """Convert various timestamp formats to UTC datetime"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.astimezone(timezone.utc)
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)
    
    def format_indicator(self, indicator_type: str, value: str) -> str:
        """Format indicator value based on type"""
        return f"[{indicator_type}] {value}" 