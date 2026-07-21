# config.py - Configuration settings for the Nigeria Cyber Intelligence Platform

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Configuration settings for the platform"""
    
    # DeepSeek API Configuration
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
    DEEPSEEK_MODEL = "deepseek-chat"
    
    # Streamlit Configuration
    APP_TITLE = "🇳🇬 Nigeria Cyber Intelligence Platform"
    APP_ICON = "🛡️"
    APP_LAYOUT = "wide"
    
    # Color Theme - Nigerian Colors
    COLORS = {
        "primary": "#008751",      # Nigerian Green
        "secondary": "#FFFFFF",    # White
        "dark_green": "#006644",   # Dark Green
        "light_green": "#00A86B",  # Light Green
        "text": "#1A1A1A",         # Dark text
        "text_light": "#FFFFFF",   # White text
        "warning": "#FFA500",      # Orange for warnings
        "danger": "#DC3545",       # Red for critical
        "success": "#28A745"       # Green for success
    }
    
    # Threat Categories
    THREAT_CATEGORIES = [
        "Phishing",
        "Ransomware",
        "Business Email Compromise (BEC)",
        "DDoS Attack",
        "Identity Theft",
        "Malware",
        "Social Engineering",
        "Data Breach",
        "419 Scam",
        "Deepfake Fraud"
    ]
    
    # Nigerian Context
    NIGERIAN_CONTEXT = {
        "critical_sectors": ["Finance", "Energy", "Telecommunications", "Government", "Healthcare"],
        "response_authorities": ["ngCERT", "NITDA", "EFCC", "NCC"],
        "common_scams": ["419", "Romance Scam", "Investment Fraud", "Fake Lottery"]
    }

# Initialize configuration
config = Config()