# nigeria_context.py - Nigeria-specific threat context and response framework

class NigeriaContext:
    """Nigeria-specific cybersecurity context and response framework"""
    
    # Nigerian Government Cybersecurity Bodies
    CYBERSECURITY_BODIES = {
        "ngCERT": {
            "name": "Nigerian Computer Emergency Response Team",
            "website": "https://cert.gov.ng",
            "email": "info@cert.gov.ng",
            "emergency": "+234 817 000 0000"
        },
        "NITDA": {
            "name": "National Information Technology Development Agency",
            "website": "https://nitda.gov.ng",
            "email": "info@nitda.gov.ng"
        },
        "EFCC": {
            "name": "Economic and Financial Crimes Commission",
            "website": "https://efcc.gov.ng",
            "email": "info@efcc.gov.ng"
        },
        "NCC": {
            "name": "Nigerian Communications Commission",
            "website": "https://ncc.gov.ng",
            "email": "contact@ncc.gov.ng"
        }
    }
    
    # Critical Infrastructure Sectors
    CRITICAL_SECTORS = {
        "finance": "Financial Services",
        "energy": "Energy & Power Grids",
        "telecom": "Telecommunications",
        "government": "Government Systems",
        "healthcare": "Healthcare & Hospitals",
        "transport": "Transportation",
        "education": "Education Institutions",
        "agriculture": "Agriculture & Food Security"
    }
    
    # Common Nigerian Threat Vectors
    THREAT_VECTORS = {
        "phishing": {
            "description": "Phishing attacks targeting Nigerian financial institutions and individuals",
            "common_patterns": ["419 emails", "Fake lottery wins", "CEO fraud", "Bank impersonation"]
        },
        "bec": {
            "description": "Business Email Compromise targeting Nigerian businesses",
            "common_patterns": ["Invoice fraud", "Payment diversion", "Executive impersonation"]
        },
        "identity_theft": {
            "description": "Identity theft using Nigerian personal data",
            "common_patterns": ["NIN theft", "BVN exploitation", "SIM swap fraud"]
        },
        "ransomware": {
            "description": "Ransomware attacks on Nigerian critical infrastructure",
            "common_patterns": ["Government systems", "Healthcare facilities", "Educational institutions"]
        }
    }
    
    @staticmethod
    def get_mitigation_strategy(threat_type: str) -> dict:
        """Return Nigeria-specific mitigation strategies for a given threat type"""
        
        strategies = {
            "phishing": {
                "immediate": [
                    "Do not click on suspicious links or download attachments",
                    "Report the incident to ngCERT immediately",
                    "Change affected passwords"
                ],
                "preventive": [
                    "Implement multi-factor authentication (MFA)",
                    "Conduct regular phishing awareness training",
                    "Use email filtering solutions"
                ],
                "authorities": ["ngCERT", "NITDA", "EFCC"]
            },
            "bec": {
                "immediate": [
                    "Contact your financial institution immediately",
                    "Verify all payment requests through secondary channels",
                    "Document all communication"
                ],
                "preventive": [
                    "Implement dual approval for financial transactions",
                    "Establish verification protocols for payment requests",
                    "Train staff on BEC recognition"
                ],
                "authorities": ["EFCC", "NITDA", "ngCERT"]
            },
            "ransomware": {
                "immediate": [
                    "Disconnect affected systems from the network",
                    "Do not pay the ransom - contact ngCERT first",
                    "Preserve evidence for investigation"
                ],
                "preventive": [
                    "Maintain offline backups",
                    "Implement network segmentation",
                    "Keep systems patched and updated"
                ],
                "authorities": ["ngCERT", "NITDA", "NCC"]
            },
            "default": {
                "immediate": [
                    "Document the incident",
                    "Preserve digital evidence",
                    "Report to ngCERT"
                ],
                "preventive": [
                    "Implement security best practices",
                    "Conduct regular security assessments",
                    "Maintain incident response plan"
                ],
                "authorities": ["ngCERT", "NITDA"]
            }
        }
        
        return strategies.get(threat_type.lower(), strategies["default"])

# Initialize context
nigeria_context = NigeriaContext()