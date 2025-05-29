from flask import Flask, render_template, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import asyncio
import logging
from api import AlienVaultClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
scheduler = BackgroundScheduler()

# Initialize threat data store
threat_data = {
    'last_update': None,
    'malware_campaigns': [],
    'phishing_sites': [],
    'malicious_ips': [],
    'threat_actors': []
}

async def fetch_threat_data():
    """Fetch threat data from all sources"""
    client = AlienVaultClient()
    try:
        # Get pulses and indicators
        pulses = await client.get_pulses(days_back=1)
        indicators = await client.get_indicators()
        
        # Update threat data store
        threat_data['malware_campaigns'] = [
            p for p in pulses if any(
                tag.lower() in ['malware', 'ransomware', 'trojan', 'botnet']
                for tag in p['tags']
            )
        ]
        
        threat_data['malicious_ips'] = [
            i for i in indicators if i['type'] in ['IPv4', 'IPv6']
        ]
        
        threat_data['last_update'] = datetime.utcnow()
        logger.info("Threat data updated successfully")
        
    except Exception as e:
        logger.error(f"Error updating threat data: {str(e)}")
    finally:
        await client.close_session()

def update_threat_data():
    """Background task to update threat intelligence data"""
    asyncio.run(fetch_threat_data())

@app.route('/')
def index():
    """Render the main dashboard"""
    return render_template('index.html', threat_data=threat_data)

@app.route('/api/threats')
def get_threats():
    """API endpoint to get current threat data"""
    return jsonify(threat_data)

def init_scheduler():
    """Initialize the background scheduler for data updates"""
    scheduler.add_job(
        update_threat_data,
        'interval',
        minutes=15,
        id='update_threat_data'
    )
    scheduler.start()
    logger.info("Scheduler initialized")

if __name__ == '__main__':
    # Initial data update
    update_threat_data()
    
    # Start the background scheduler
    init_scheduler()
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000) 