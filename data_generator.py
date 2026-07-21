# data_generator.py - Generate simulated threat data for testing

import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

class ThreatDataGenerator:
    """Generate simulated threat data for platform testing and demonstration"""
    
    # Nigerian threat templates
    PHISHING_TEMPLATES = [
        {
            "subject": "Urgent: Account Verification Required",
            "body": "Dear Customer, Your account has been flagged for unusual activity. Click the link to verify: {link}",
            "indicators": ["phishing", "urgent", "verify", "account", "link"]
        },
        {
            "subject": "NIN Update Required - Action Needed",
            "body": "Your National Identification Number needs verification. Complete your NIN update: {link}",
            "indicators": ["phishing", "NIN", "verification", "update"]
        },
        {
            "subject": "Inheritance Claim Notification",
            "body": "Dear Beneficiary, You have been awarded $10,000,000 from the Nigerian National Lottery. Contact: {contact}",
            "indicators": ["419", "inheritance", "lottery", "beneficiary"]
        }
    ]
    
    BEC_TEMPLATES = [
        {
            "subject": "URGENT: Payment Approval Required",
            "body": "CEO is in a meeting. Please process the attached invoice immediately. Wire to account: {account}",
            "indicators": ["bec", "payment", "invoice", "urgent", "wire"]
        },
        {
            "subject": "Confidential: Supplier Payment",
            "body": "Please process payment to our new supplier. Details attached. Confidential - CEO approval obtained.",
            "indicators": ["bec", "confidential", "payment", "supplier", "CEO"]
        }
    ]
    
    RANSOMWARE_TEMPLATES = [
        {
            "subject": "SYSTEM COMPROMISED - ENCRYPTION IN PROGRESS",
            "body": "Your files have been encrypted. Pay 5 BTC to recover. Deadline: 48 hours. Decrypt key: {key}",
            "indicators": ["ransomware", "encrypted", "bitcoin", "decrypt", "deadline"]
        }
    ]
    
    @staticmethod
    def generate_phishing_email() -> Dict[str, Any]:
        """Generate a simulated phishing email"""
        template = random.choice(ThreatDataGenerator.PHISHING_TEMPLATES)
        link = f"https://{random.choice(['secure', 'verify', 'update', 'account'])}-{random.randint(1000,9999)}.{random.choice(['com', 'net', 'org'])}"
        
        return {
            "type": "phishing",
            "subject": template["subject"],
            "body": template["body"].format(link=link, contact="info@claim-center.net"),
            "sender": f"{random.choice(['support', 'admin', 'security', 'verify'])}@{random.choice(['bank', 'gov', 'nitda', 'ncc'])}.ng",
            "timestamp": datetime.now().isoformat(),
            "indicators": template["indicators"]
        }
    
    @staticmethod
    def generate_bec_email() -> Dict[str, Any]:
        """Generate a simulated BEC email"""
        template = random.choice(ThreatDataGenerator.BEC_TEMPLATES)
        account = f"{random.randint(1000000000, 9999999999)}"
        
        return {
            "type": "bec",
            "subject": template["subject"],
            "body": template["body"].format(account=account),
            "sender": f"{random.choice(['ceo', 'cfo', 'finance', 'accounting'])}@{random.choice(['company', 'firm', 'corp'])}.ng",
            "timestamp": datetime.now().isoformat(),
            "indicators": template["indicators"]
        }
    
    @staticmethod
    def generate_ransomware_alert() -> Dict[str, Any]:
        """Generate a simulated ransomware alert"""
        template = random.choice(ThreatDataGenerator.RANSOMWARE_TEMPLATES)
        key = f"ID-{random.randint(10000, 99999)}-{random.choice(['A','B','C','D'])}"
        
        return {
            "type": "ransomware",
            "subject": template["subject"],
            "body": template["body"].format(key=key),
            "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "timestamp": datetime.now().isoformat(),
            "indicators": template["indicators"]
        }
    
    @staticmethod
    def generate_threat_dataset(count: int = 10) -> List[Dict[str, Any]]:
        """Generate a dataset of simulated threats"""
        threats = []
        generators = [
            ThreatDataGenerator.generate_phishing_email,
            ThreatDataGenerator.generate_bec_email,
            ThreatDataGenerator.generate_ransomware_alert
        ]
        
        for _ in range(count):
            generator = random.choice(generators)
            threats.append(generator())
        
        return threats

# Initialize generator
data_generator = ThreatDataGenerator()