# threat_analyzer.py - Core threat analysis using DeepSeek API

import requests
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import streamlit as st

from config import config
from nigeria_context import nigeria_context

class DeepSeekThreatAnalyzer:
    """AI-assisted threat analyzer using DeepSeek API with Nigerian context"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the threat analyzer with DeepSeek API key"""
        self.api_key = api_key or config.DEEPSEEK_API_KEY
        self.api_url = config.DEEPSEEK_API_URL
        self.model = config.DEEPSEEK_MODEL
        
    def analyze_threat(self, threat_data: str, threat_type: str = "general") -> Dict[str, Any]:
        """
        Analyze threat data and return comprehensive analysis
        
        Args:
            threat_data: The threat description or input data
            threat_type: Type of threat (phishing, malware, etc.)
            
        Returns:
            Dictionary containing classification, threat level, explanation, mitigations
        """
        if not self.api_key or self.api_key == "":
            return self._get_demo_analysis(threat_data, threat_type)
        
        try:
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt(threat_data, threat_type)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 2000
            }
            
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=60)
            
            if response.status_code == 200:
                return self._parse_response(response.json(), threat_data)
            else:
                return self._get_demo_analysis(threat_data, threat_type)
                
        except Exception as e:
            print(f"Error analyzing threat: {e}")
            return self._get_demo_analysis(threat_data, threat_type)
    
    def _build_system_prompt(self) -> str:
        """Build the system prompt for DeepSeek API"""
        return """
        You are a Nigerian cybersecurity expert with deep knowledge of the Nigerian threat landscape.
        
        Analyze the provided threat data and provide a structured analysis with the following sections:
        
        1. **Classification**: Identify the type of threat (Phishing, Ransomware, BEC, DDoS, Identity Theft, Malware, Social Engineering, Data Breach, 419 Scam, Deepfake Fraud)
        
        2. **Threat Level**: Assess as LOW, MEDIUM, HIGH, or CRITICAL
        
        3. **Explanation**: Provide a clear, detailed explanation of the threat, including:
           - How the attack works
           - Why it's particularly relevant in Nigeria
           - Potential impact on Nigerian organizations/individuals
        
        4. **Mitigation Steps**: Provide 4-6 specific, actionable steps for:
           - Immediate response (what to do right now)
           - Prevention (how to protect against future attacks)
        
        5. **Confidence Score**: Rate your confidence in this analysis (0-100%)
        
        6. **Relevant Authorities**: Specify which Nigerian authorities should be contacted
        
        Format your response with clear section headers and bullet points for easy reading.
        """
    
    def _build_user_prompt(self, threat_data: str, threat_type: str) -> str:
        """Build the user prompt with threat data and context"""
        context = nigeria_context
        
        prompt = f"""
        THREAT TYPE: {threat_type}
        THREAT DATA:
        {threat_data}
        
        NIGERIAN CONTEXT:
        - Critical Sectors: {', '.join(context.CRITICAL_SECTORS.keys())}
        - Authorities: {', '.join(context.CYBERSECURITY_BODIES.keys())}
        - Common Scams: 419, Romance Scam, Investment Fraud, Fake Lottery
        
        Please analyze this threat considering the Nigerian digital environment.
        """
        
        return prompt
    
    def _parse_response(self, response_data: Dict, original_input: str) -> Dict[str, Any]:
        """Parse DeepSeek API response into structured format"""
        try:
            content = response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            # Extract structured information
            analysis = self._extract_sections(content)
            
            return {
                "classification": analysis.get("classification", "Unknown"),
                "threat_level": analysis.get("threat_level", "MEDIUM"),
                "explanation": analysis.get("explanation", content),
                "mitigations": analysis.get("mitigations", []),
                "confidence": int(analysis.get("confidence", 85)),
                "authorities": analysis.get("authorities", ["ngCERT", "NITDA"]),
                "raw_response": content,
                "timestamp": datetime.now().isoformat(),
                "input": original_input
            }
            
        except Exception as e:
            print(f"Error parsing response: {e}")
            return self._get_demo_analysis(original_input, "general")
    
    def _extract_sections(self, content: str) -> Dict[str, Any]:
        """Extract structured sections from API response"""
        sections = {
            "classification": "Unknown",
            "threat_level": "MEDIUM",
            "explanation": content,
            "mitigations": [],
            "confidence": 85,
            "authorities": ["ngCERT", "NITDA"]
        }
        
        lines = content.split('\n')
        current_section = None
        mitigation_lines = []
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Detect section headers
            if 'classification' in line_lower or 'threat type' in line_lower:
                current_section = 'classification'
                # Extract value after colon
                if ':' in line:
                    sections['classification'] = line.split(':', 1)[1].strip()
            elif 'threat level' in line_lower or 'severity' in line_lower:
                current_section = 'threat_level'
                if ':' in line:
                    level = line.split(':', 1)[1].strip().upper()
                    if level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                        sections['threat_level'] = level
            elif 'mitigation' in line_lower or 'recommend' in line_lower or 'steps' in line_lower:
                current_section = 'mitigations'
            elif 'confidence' in line_lower:
                current_section = 'confidence'
                # Extract number from string
                numbers = re.findall(r'\d+', line)
                if numbers:
                    sections['confidence'] = min(int(numbers[0]), 100)
            elif 'authorit' in line_lower or 'contact' in line_lower:
                current_section = 'authorities'
                if ':' in line:
                    authorities = line.split(':', 1)[1].strip()
                    # Extract authority names
                    found = []
                    for auth in ['ngCERT', 'NITDA', 'EFCC', 'NCC']:
                        if auth.lower() in authorities.lower():
                            found.append(auth)
                    if found:
                        sections['authorities'] = found
            
            # Collect mitigation steps
            if current_section == 'mitigations':
                if line.strip().startswith(('-', '•', '*', '1.', '2.', '3.', '4.')):
                    mitigation_lines.append(line.strip())
        
        # If no mitigations found, try to extract from content
        if not mitigation_lines:
            # Look for numbered or bulleted lists
            for line in lines:
                if line.strip().startswith(('-', '•', '*', '1.', '2.', '3.', '4.', '5.', '6.')):
                    mitigation_lines.append(line.strip())
        
        sections['mitigations'] = mitigation_lines[:8]  # Limit to 8 mitigations
        
        return sections
    
    def _get_demo_analysis(self, threat_data: str, threat_type: str) -> Dict[str, Any]:
        """Return demo analysis when API is not available"""
        
        # Determine threat classification from keywords
        threat_data_lower = threat_data.lower()
        
        classifications = {
            "phishing": ["phishing", "email", "click", "link", "urgent", "bank", "password"],
            "ransomware": ["ransom", "encrypt", "decrypt", "bitcoin", "payment"],
            "bec": ["ceo", "invoice", "payment", "transfer", "urgent", "wire"],
            "ddos": ["ddos", "flood", "traffic", "down", "attack"],
            "identity": ["nin", "bvn", "identity", "stolen", "credit"],
            "419": ["419", "prince", "inheritance", "lottery", "winning"]
        }
        
        classification = "Unknown"
        for cat, keywords in classifications.items():
            if any(keyword in threat_data_lower for keyword in keywords):
                classification = cat.upper()
                break
        
        # Get context-specific mitigations
        mitigation_data = nigeria_context.get_mitigation_strategy(classification)
        
        return {
            "classification": classification,
            "threat_level": "HIGH" if classification == "RANSOMWARE" else "MEDIUM",
            "explanation": f"""
            This appears to be a {classification} attack targeting Nigerian systems.
            
            Analysis indicates this threat leverages techniques commonly used against Nigerian organizations,
            particularly in the financial and government sectors.
            
            The attack exploits vulnerabilities in human factors and system configurations.
            """,
            "mitigations": mitigation_data.get("immediate", []) + mitigation_data.get("preventive", []),
            "confidence": 80,
            "authorities": mitigation_data.get("authorities", ["ngCERT", "NITDA"]),
            "raw_response": f"Demo analysis for {classification} threat",
            "timestamp": datetime.now().isoformat(),
            "input": threat_data,
            "is_demo": True
        }

# Initialize analyzer
analyzer = DeepSeekThreatAnalyzer()