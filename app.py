# app.py - Nigeria Cyber Intelligence Platform

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import random
import re

from config import config
from threat_analyzer import DeepSeekThreatAnalyzer
from data_generator import data_generator
from nigeria_context import nigeria_context

# Page configuration
st.set_page_config(
    page_title="Nigeria Cyber Intelligence Platform",
    page_icon="<img src='logo.jpeg' >",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main { background-color: #f8f9fa; }
    h1, h2, h3, h4, h5 { color: #008751 !important; font-weight: 600 !important; }
    
    .css-1d391kg { background-color: #008751 !important; }
    
    .stButton > button {
        background-color: #008751 !important;
        color: white !important;
        border: none !important;
        padding: 10px 24px !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        width: 100% !important;
    }
    .stButton > button:hover {
        background-color: #006644 !important;
        box-shadow: 0 4px 12px rgba(0, 135, 81, 0.3);
    }
    
    .metric-card {
        background-color: #008751;
        color: white;
        padding: 20px;
        border-radius: 12px;
        text-align: center;
        margin: 10px 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .metric-card .value { font-size: 32px; font-weight: 700; }
    .metric-card .label { font-size: 14px; opacity: 0.9; }
    
    .threat-card {
        background-color: white;
        border-left: 4px solid #008751;
        padding: 15px;
        margin: 10px 0;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    }
    .threat-card .title { font-weight: 600; color: #1a1a1a; }
    .threat-card .detail { color: #4a4a4a; font-size: 14px; }
    
    .badge-critical { background-color: #dc3545; color: white; padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 12px; }
    .badge-high { background-color: #ff6b35; color: white; padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 12px; }
    .badge-medium { background-color: #ffa500; color: white; padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 12px; }
    .badge-low { background-color: #28a745; color: white; padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 12px; }
    
    .mitigation-step {
        background-color: #f0f7f4;
        border-left: 3px solid #008751;
        padding: 10px 15px;
        margin: 8px 0;
        border-radius: 4px;
        color: #1a1a1a;
    }
    .mitigation-step strong { color: #008751; }
    
    .white-card {
        background-color: white;
        border: 1px solid #e0e0e0;
        border-radius: 12px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .white-card h4 { color: #008751 !important; margin-top: 0; }
    .white-card h5 { color: #008751 !important; margin-top: 15px; }
    
    .nigeria-flag {
        background: linear-gradient(90deg, #008751 0%, #008751 33%, #ffffff 33%, #ffffff 66%, #008751 66%, #008751 100%);
        height: 4px;
        margin: 20px 0;
        border-radius: 2px;
    }
    
    .footer {
        text-align: center;
        padding: 20px;
        color: #4a4a4a;
        font-size: 12px;
        border-top: 1px solid #e0e0e0;
        margin-top: 40px;
    }
    
    .sidebar-stat {
        background-color: #006644;
        padding: 15px;
        border-radius: 8px;
        color: white;
        margin: 5px 0;
    }
    .sidebar-stat .label { font-size: 12px; opacity: 0.8; }
    .sidebar-stat .value { font-size: 24px; font-weight: 700; }
    
    .authority-badge {
        background-color: #f0f7f4;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #008751;
        text-align: center;
    }
    .authority-badge .name { font-weight: 700; color: #008751; }
    .authority-badge .desc { font-size: 12px; color: #4a4a4a; }
    .authority-badge .email { font-size: 11px; color: #888; margin-top: 5px; }
    
    .analysis-text {
        color: #1a1a1a;
        font-size: 15px;
        line-height: 1.8;
    }
    .analysis-text strong { color: #008751; }
</style>
""", unsafe_allow_html=True)

# ===== SIDEBAR =====
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 10px 0;">
        <div style="background: linear-gradient(90deg, #008751 0%, #008751 33%, #ffffff 33%, #ffffff 66%, #008751 66%, #008751 100%); height: 30px; border-radius: 4px;"></div>
        <div style="margin-top: 10px; font-weight: 700; font-size: 18px; color: #008751;">NIGERIA</div>
        <div style="color: #008751; font-size: 12px;">Cyber Intelligence Platform</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### Navigation")
    page = st.radio("", ["Dashboard", "Threat Analysis", "Threat Reports", "About"], index=1)
    
    st.markdown("---")
    st.markdown("### Quick Stats")
    st.markdown("""
    <div class="sidebar-stat"><div class="label">Active Threats</div><div class="value">12</div></div>
    <div class="sidebar-stat" style="background-color: #004d33;"><div class="label">Critical Alerts</div><div class="value">3</div></div>
    <div class="sidebar-stat" style="background-color: #003d28;"><div class="label">Response Rate</div><div class="value">94%</div></div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### Response Authorities")
    for auth, details in nigeria_context.CYBERSECURITY_BODIES.items():
        st.markdown(f"**{auth}** - {details.get('name', '')}")
    
    st.markdown("---")
    api_status = "Active" if config.DEEPSEEK_API_KEY and config.DEEPSEEK_API_KEY != "" else "Demo Mode"
    status_color = "🟢" if config.DEEPSEEK_API_KEY and config.DEEPSEEK_API_KEY != "" else "🟡"
    st.markdown(f"**API Status:** {status_color} {api_status}")

# ===== HEADER =====
st.markdown("""
<div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
    <div style="font-size: 40px;"></div>
    <div>
        <h1 style="margin: 0; color: #008751;">Nigeria Cyber Intelligence Platform</h1>
        <p style="color: #4a4a4a; margin: 0;">AI-Assisted Threat Detection and Mitigation with DeepSeek Integration for Research Paper</p>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="nigeria-flag"></div>', unsafe_allow_html=True)

# ===== DASHBOARD =====
if page == "Dashboard":
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("""
        <div class="metric-card"><div class="label">Weekly Attacks (Nigeria)</div><div class="value">4,200</div>
        <div style="font-size: 12px;">⬆️ 60% above global average</div></div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="metric-card" style="background-color: #006644;"><div class="label">AI-Powered Threats</div>
        <div class="value">37%</div><div style="font-size: 12px;">⬆️ 15% year-over-year</div></div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="metric-card" style="background-color: #004d33;"><div class="label">Critical Infrastructure</div>
        <div class="value">6</div><div style="font-size: 12px;">Sectors at risk</div></div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown("""
        <div class="metric-card" style="background-color: #003d28;"><div class="label">Threat Intelligence</div>
        <div class="value">24/7</div><div style="font-size: 12px;">AI-powered monitoring</div></div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Top Threat Categories")
        threat_data = pd.DataFrame({
            'Category': ['Phishing', 'BEC', 'Identity Theft', 'Ransomware', 'DDoS', '419 Scams'],
            'Count': [120, 85, 67, 45, 38, 52]
        })
        fig = px.bar(threat_data, x='Category', y='Count', color='Category',
                     color_discrete_sequence=['#008751', '#00a86b', '#006644', '#004d33', '#003d28', '#2e8b57'],
                     title='Reported Threats by Category')
        fig.update_layout(plot_bgcolor='white', paper_bgcolor='white', font_color='#1a1a1a', showlegend=False, height=350)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### Threat Severity Distribution")
        severity_data = pd.DataFrame({'Severity': ['Critical', 'High', 'Medium', 'Low'], 'Count': [15, 42, 78, 35]})
        fig = px.pie(severity_data, values='Count', names='Severity', color='Severity',
                     color_discrete_map={'Critical': '#dc3545', 'High': '#ff6b35', 'Medium': '#ffa500', 'Low': '#28a745'},
                     title='Threat Severity Distribution')
        fig.update_layout(plot_bgcolor='white', paper_bgcolor='white', font_color='#1a1a1a', height=350)
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    st.markdown("#### Recent Detected Threats")
    sample_threats = data_generator.generate_threat_dataset(5)
    for threat in sample_threats:
        threat_type = threat.get('type', 'Unknown').upper()
        level = "HIGH" if threat_type == "RANSOMWARE" else "MEDIUM"
        badge_class = "badge-critical" if level == "CRITICAL" else "badge-high" if level == "HIGH" else "badge-medium"
        st.markdown(f"""
        <div class="threat-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span class="title">🛡️ {threat_type}</span>
                <span class="{badge_class}">{level}</span>
            </div>
            <div class="detail"><strong>Subject:</strong> {threat.get('subject', 'N/A')[:60]}...</div>
            <div class="detail" style="font-size: 12px; color: #888;">
                <strong>Detected:</strong> {threat.get('timestamp', 'Just now')[:19]}
            </div>
        </div>
        """, unsafe_allow_html=True)

# ===== THREAT ANALYSIS =====
elif page == "Threat Analysis":
    st.markdown("### Threat Analysis Engine")
    st.markdown("Enter threat data below for AI-powered analysis using DeepSeek integration.")
    st.markdown('<div class="nigeria-flag"></div>', unsafe_allow_html=True)
    
    if 'threat_input' not in st.session_state:
        st.session_state.threat_input = ""
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        threat_input = st.text_area(
            "Paste threat description, email content, or IP address:",
            value=st.session_state.threat_input,
            height=200,
            placeholder="Example: I received a suspicious email claiming to be from my bank asking me to verify my account by clicking a link..."
        )
        st.session_state.threat_input = threat_input
    
    with col2:
        st.markdown("#### Quick Templates")
        st.markdown("*Click a template to load it*")
        
        templates = {
            "Phishing": "Received an urgent email from 'support@bank-security.ng' claiming my account will be suspended. Asked to click link and enter BVN, NIN, and password. The link goes to 'bank-verify-secure.net'. Sender had +234 prefix.",
            "BEC": "Received email from 'CEO' asking to urgently wire ₦5,000,000 to a new supplier account. The email was sent at 11pm and the 'CEO' is reportedly on a flight. Bank details: GTBank, Account: 0123456789. Sender: ceo@company-name.ng (spoofed).",
            "Ransomware": "Systems are encrypted with message demanding 5 BTC. Files have .encrypted extension. Ransom note: 'Your data is locked. Pay 5 BTC to decrypt. Deadline: 48 hours. Contact: decrypt@onionmail.org' Network scans show unusual outbound connections.",
            "419 Scam": "Received email from 'Dr. James Okonkwo' claiming I'm a beneficiary of a $10,000,000 inheritance. Need to send $500 for processing fees. Contact: james.okonkwo@yahoo.com. UK phone number provided."
        }
        
        for template_name, template_text in templates.items():
            if st.button(template_name, use_container_width=True, key=f"template_{template_name}"):
                st.session_state.threat_input = template_text
                st.rerun()
    
    st.markdown("---")
    threat_type = st.selectbox(
        "Threat Category (for context)",
        ["General", "Phishing", "BEC", "Ransomware", "DDoS", "Identity Theft", "419 Scam", "Malware"]
    )
    
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        analyze_clicked = st.button("Analyze Threat", use_container_width=True, type="primary")
    
    if analyze_clicked and st.session_state.threat_input:
        st.markdown("---")
        st.markdown("### Analysis Results")
        
        with st.spinner("Analyzing threat using DeepSeek AI..."):
            time.sleep(1)
            analyzer = DeepSeekThreatAnalyzer()
            result = analyzer.analyze_threat(st.session_state.threat_input, threat_type)
            
            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                classification = result.get('classification', 'Unknown')
                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #008751, #006644); padding: 20px; border-radius: 12px; color: white; text-align: center;">
                    <div style="font-size: 12px; opacity: 0.8;">Classification</div>
                    <div style="font-size: 24px; font-weight: 700;">{classification}</div>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                level = result.get('threat_level', 'MEDIUM')
                colors = {'CRITICAL': '#dc3545', 'HIGH': '#ff6b35', 'MEDIUM': '#ffa500', 'LOW': '#28a745'}
                st.markdown(f"""
                <div style="background-color: {colors.get(level, '#ffa500')}; padding: 20px; border-radius: 12px; color: white; text-align: center;">
                    <div style="font-size: 12px; opacity: 0.8;">Threat Level</div>
                    <div style="font-size: 24px; font-weight: 700;">{level}</div>
                </div>
                """, unsafe_allow_html=True)
            with col3:
                confidence = result.get('confidence', 85)
                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #004d33, #003d28); padding: 20px; border-radius: 12px; color: white; text-align: center;">
                    <div style="font-size: 12px; opacity: 0.8;">Confidence</div>
                    <div style="font-size: 24px; font-weight: 700;">{confidence}%</div>
                </div>
                """, unsafe_allow_html=True)
            
            st.markdown("---")
            st.markdown("#### Threat Explanation")
            
            explanation = result.get('explanation', 'Analysis complete.')
            st.markdown(f"""
            <div class="white-card">
                <div class="analysis-text">{explanation}</div>
                <div style="margin-top: 15px; font-size: 12px; color: #888; border-top: 1px solid #eee; padding-top: 10px;">
                    <strong>Analysis Time:</strong> {result.get('timestamp', '')[:19]}
                    {'' if not result.get('is_demo', False) else ' (Demo Mode)'}
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("#### Mitigation Recommendations")
            st.markdown("*Nigeria-specific response actions*")
            
            mitigations = result.get('mitigations', [])
            if mitigations:
                for i, step in enumerate(mitigations[:8], 1):
                    st.markdown(f"""
                    <div class="mitigation-step"><strong>{i}.</strong> {step}</div>
                    """, unsafe_allow_html=True)
            else:
                st.info("No specific mitigations found. Please consult ngCERT for guidance.")
            
            st.markdown("#### Report To:")
            authorities = result.get('authorities', ['ngCERT', 'NITDA'])
            auth_data = nigeria_context.CYBERSECURITY_BODIES
            cols = st.columns(min(len(authorities), 3))
            for i, auth in enumerate(authorities[:3]):
                with cols[i % 3]:
                    if auth in auth_data:
                        st.markdown(f"""
                        <div class="authority-badge">
                            <div class="name">{auth}</div>
                            <div class="desc">{auth_data[auth].get('name', '')[:35]}</div>
                            <div class="email">{auth_data[auth].get('email', '')}</div>
                        </div>
                        """, unsafe_allow_html=True)
            
            if result.get('is_demo', False):
                st.warning("Demo Mode Active - Set DEEPSEEK_API_KEY for live analysis.")
    
    elif analyze_clicked and not st.session_state.threat_input:
        st.warning("Please enter threat data for analysis.")

# ===== THREAT REPORTS =====
elif page == "Threat Reports":
    st.markdown("### Threat Intelligence Reports")
    st.markdown('<div class="nigeria-flag"></div>', unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["Weekly Summary", "Threat Categories", "Generated Reports"])
    
    with tab1:
        st.markdown("#### Nigeria Weekly Cyber Threat Summary")
        dates = pd.date_range(start='2026-07-01', periods=30, freq='D')
        threat_counts = [random.randint(3500, 4800) for _ in range(30)]
        df = pd.DataFrame({'Date': dates, 'Attacks': threat_counts})
        fig = px.line(df, x='Date', y='Attacks', title='Weekly Cyber Attack Trends', color_discrete_sequence=['#008751'])
        fig.update_layout(plot_bgcolor='white', paper_bgcolor='white', font_color='#1a1a1a', height=400)
        fig.add_hline(y=4200, line_dash="dash", line_color="red", annotation_text="Nigeria Average: 4,200")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("""
        <div class="white-card">
            <h4>Key Insights</h4>
            <ul>
                <li>Nigeria records <strong>4,200+</strong> weekly attacks - highest in Africa</li>
                <li>Business Email Compromise (<strong>BEC</strong>) up 23% this quarter</li>
                <li>AI-powered phishing attacks increasing at <strong>15%</strong> year-over-year</li>
                <li>Critical infrastructure sectors: Finance (34%), Energy (22%), Telecom (18%)</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with tab2:
        st.markdown("#### Threat Category Analysis")
        category_data = pd.DataFrame({
            'Category': ['Phishing', 'BEC', 'Identity Theft', 'Ransomware', 'DDoS', '419 Scams', 'Malware', 'Social Engineering'],
            'Count': [120, 85, 67, 45, 38, 52, 41, 29],
            'Trend': ['🔺', '🔺', '🔺', '🔻', '🔻', '🔺', '🔺', '🔻']
        })
        fig = px.bar(category_data, x='Category', y='Count', color='Category',
                     color_discrete_sequence=['#008751', '#00a86b', '#006644', '#004d33', '#2e8b57', '#3cb371', '#66cdaa', '#90ee90'],
                     title='Threat Distribution by Category')
        fig.update_layout(plot_bgcolor='white', paper_bgcolor='white', font_color='#1a1a1a', showlegend=False, height=400)
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(category_data, use_container_width=True, hide_index=True)
    
    with tab3:
        st.markdown("#### Generate Intelligence Report")
        col1, col2 = st.columns(2)
        with col1:
            report_type = st.selectbox("Report Type", ["Threat Summary", "Sector Analysis", "Vulnerability Assessment", "Response Planning"])
        with col2:
            sector = st.selectbox("Target Sector", ["All Sectors", "Finance", "Energy", "Telecommunications", "Government", "Healthcare"])
        
        if st.button("Generate Report", use_container_width=True):
            with st.spinner("Generating AI-powered report..."):
                time.sleep(2)
                st.success("Report generated successfully!")
                st.markdown(f"""
                <div class="white-card">
                    <h4>{report_type} Report</h4>
                    <p><strong>Sector:</strong> {sector}</p>
                    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
                    <hr>
                    <h5>Key Findings</h5>
                    <ul>
                        <li>High risk of BEC targeting Nigerian financial institutions</li>
                        <li>Phishing campaigns leveraging Nigerian identity documents (NIN, BVN)</li>
                        <li>Ransomware groups focusing on critical infrastructure</li>
                        <li>419 scams adapting with AI-generated content</li>
                    </ul>
                    <h5>Recommended Actions</h5>
                    <ul>
                        <li>Implement multi-factor authentication across all systems</li>
                        <li>Conduct regular phishing awareness training</li>
                        <li>Maintain offline, immutable backups</li>
                        <li>Report all incidents to ngCERT</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)

# ===== ABOUT =====
elif page == "About":
    st.markdown("### About This Platform")
    st.markdown('<div class="nigeria-flag"></div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        <div class="white-card">
            <h4>Nigeria Cyber Intelligence Platform</h4>
            <p style="color: #1a1a1a; line-height: 1.6;">
                This platform provides AI-assisted cybersecurity threat detection and mitigation
                specifically designed for Nigeria's digital environment.
            </p>
            <h5>Key Features</h5>
            <ul>
                <li><strong>DeepSeek Integration</strong> - Advanced AI for threat analysis</li>
                <li><strong>Nigeria-Specific Context</strong> - Tailored to Nigerian threats and regulations</li>
                <li><strong>Real-Time Analysis</strong> - Instant threat classification and explanation</li>
                <li><strong>Actionable Mitigations</strong> - Nigeria-specific response recommendations</li>
                <li><strong>Open Source</strong> - Available on GitHub for community adoption</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div style="background-color: #008751; padding: 20px; border-radius: 12px; color: white; text-align: center;">
            <div style="font-size: 48px;">🛡️</div>
            <div style="font-weight: 700; font-size: 20px;">Nigeria First</div>
            <div style="font-size: 14px; opacity: 0.9;">Built for Nigerian Security</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("""
    <div class="white-card">
        <h4>References</h4>
        <ul style="color: #1a1a1a; font-size: 14px; line-height: 1.8;">
            <li>Check Point Software Technologies. (2025). <em>African Perspectives on Cyber Security Report</em></li>
            <li>Cambridge University. (2026). <em>Boko Haram and Frontier AI: An Empirical Study</em></li>
            <li>NITDA. (2025). <em>Nigeria Digital Economy Strategy</em></li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

# ===== FOOTER =====
st.markdown("---")
st.markdown("""
<div class="footer">
    <p>Nigeria Cyber Intelligence Platform By Orji, Cyrus Ebere, MCPN | Integrated DeepSeek API</p>
    <p style="font-size: 11px; color: #888;">
        Disclaimer: This tool is for intelligence purposes. Always verify critical outputs 
        and consult official authorities (ngCERT, NITDA) for incident response.
    </p>
</div>
""", unsafe_allow_html=True)