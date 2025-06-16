import streamlit as st
import pandas as pd
import time
import plotly.express as px
import re
import socket
import ssl
import whois
import requests
import math
import urllib.parse
import dns.resolver
import ipaddress
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from collections import Counter

# Import the functions from your original script
from paste import (
    is_ipv4, is_ipv6, is_decimal_ip, is_hex_ip, is_octal_ip,
    check_ip_in_domain, extract_url_features
)

# Set page configuration
st.set_page_config(
    page_title="URL Phishing Detection",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Sidebar
with st.sidebar:
    st.title("🔒 Phishing URL Detector")
    st.write("This tool analyzes URLs to detect potential phishing attempts based on multiple features.")
    
    st.subheader("How to use")
    st.write("1. Enter a URL in the input box")
    st.write("2. Click 'Analyze URL' to start the analysis")
    st.write("3. Review the detailed results")
    
    st.subheader("About")
    st.write("""
    This tool extracts over 50 features from the URL and webpage content to identify 
    potential phishing attempts. Features include domain characteristics, SSL information,
    content analysis, and more.
    """)
    
    st.divider()
    st.write("© 2025 Phishing Detection Tool")

# Main content
st.title("URL Phishing Detection Dashboard")

# URL input
url_input = st.text_input("Enter a URL to analyze:", placeholder="example.com or https://example.com")

analyze_button = st.button("Analyze URL", type="primary")

if analyze_button and url_input:
    # Add http:// prefix if missing
    if not url_input.startswith('http'):
        url_input = 'http://' + url_input
        
    # Display the URL being analyzed
    st.info(f"Analyzing URL: {url_input}")
    
    # Progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Start timer
        start_time = time.time()
        status_text.text("Extracting features...")
        
        # Extract features
        features = extract_url_features(url_input)
        
        # Update progress
        progress_bar.progress(100)
        status_text.text("Analysis complete!")
        
        # Calculate time taken
        time_taken = time.time() - start_time
        
        # Display results
        st.success(f"URL Feature Extraction Complete in {time_taken:.2f} seconds")
        
        # Create three columns for the metrics
        col1, col2, col3 = st.columns(3)
        
        # Security indicators
        with col1:
            ssl_state = "Secure" if features["SSLfinal_State"] == 1 else "Not Secure"
            ssl_color = "green" if features["SSLfinal_State"] == 1 else "red"
            st.metric("SSL Status", ssl_state)
        
        with col2:
            ip_address = "Yes" if features["having_IP_Address"] == 1 else "No"
            ip_color = "red" if features["having_IP_Address"] == 1 else "green"
            st.metric("IP Address as Domain", ip_address)
            
        with col3:
            domain_age = f"{features['age_of_domain']} days" if features["age_of_domain"] > 0 else "Unknown"
            st.metric("Domain Age", domain_age)
        
        # Create tabs for different categories of features
        tab1, tab2, tab3, tab4 = st.tabs(["Domain Features", "Page Content", "Security Checks", "Advanced Features"])
        
        with tab1:
            st.subheader("Domain & URL Features")
            
            domain_features = {
                "URL Length": features["URL_Length"],
                "Using Shortening Service": "Yes" if features["Shortening_Service"] == 1 else "No",
                "Has @ Symbol": "Yes" if features["having_At_Symbol"] == 1 else "No",
                "Double Slash Redirect": "Yes" if features["double_slash_redirecting"] == 1 else "No",
                "Has Prefix/Suffix Dash": "Yes" if features["Prefix_Suffix"] == 1 else "No",
                "Number of Subdomains": features["having_Sub_Domain"],
                "Domain Registration Length": f"{features['Domain_registeration_length']} days" if features["Domain_registeration_length"] > 0 else "Unknown",
                "Non-Standard Port": "Yes" if features["port"] == 1 else "No",
                "HTTPS in Domain": "Yes" if features["HTTPS_token"] == 1 else "No",
                "URL Entropy": f"{features['entropy_of_url']:.2f}",
                "Ratio of Digits": f"{features['ratio_digits']:.2f}",
                "Contains Login Keywords": "Yes" if features["contains_login_keywords"] == 1 else "No",
                "URL is Encoded": "Yes" if features["url_is_encoded"] == 1 else "No"
            }
            
            # Create a DataFrame for better display
            df_domain = pd.DataFrame(list(domain_features.items()), columns=["Feature", "Value"])
            st.table(df_domain)
            
            # Create chart for domain features
            numeric_domain_features = {
                "URL Length": features["URL_Length"],
                "Number of Subdomains": features["having_Sub_Domain"],
                "URL Entropy": features["entropy_of_url"],
                "Ratio of Digits": features["ratio_digits"]
            }
            
            df_chart = pd.DataFrame({
                'Feature': list(numeric_domain_features.keys()),
                'Value': list(numeric_domain_features.values())
            })
            
            fig = px.bar(df_chart, x='Feature', y='Value', title='Numeric URL Features',
                         color='Value', color_continuous_scale='Viridis')
            st.plotly_chart(fig, use_container_width=True)
            
        with tab2:
            st.subheader("Page Content Analysis")
            
            if features["html_length"] > 0:  # Check if content was retrieved
                content_features = {
                    "External Resources Ratio": f"{features['Request_URL']:.2f}",
                    "External Links Ratio": f"{features['URL_of_Anchor']:.2f}",
                    "Meta/Script/Link Tags Ratio": f"{features['Links_in_tags']:.2f}",
                    "Form Action Empty/Blank": "Yes" if features["SFH"] == 1 else "No",
                    "Submitting to Email": "Yes" if features["Submitting_to_email"] == 1 else "No",
                    "OnMouseOver Changes Status Bar": "Yes" if features["on_mouseover"] == 1 else "No",
                    "Right Click Disabled": "Yes" if features["RightClick"] == 1 else "No",
                    "Uses Popup Windows": "Yes" if features["popUpWidnow"] == 1 else "No",
                    "Uses Iframe": "Yes" if features["Iframe"] == 1 else "No",
                    "HTML Length": features["html_length"],
                    "JS Obfuscation Score": features["js_obfuscation_score"],
                    "External Script Count": features["external_script_count"],
                    "JS Eval Function Count": features["js_eval_function_count"],
                    "Form Count": features["form_count"],
                    "Form Action Matches Domain": "Yes" if features["form_action_matches_domain"] == 1 else "No",
                    "Suspicious Title Keywords": "Yes" if features["title_tag_keywords"] == 1 else "No"
                }
                
                df_content = pd.DataFrame(list(content_features.items()), columns=["Feature", "Value"])
                st.table(df_content)
                
                # Create pie chart for form-related features
                form_features = {
                    "Forms Present": features["form_count"],
                    "Email Submission Form": features["Submitting_to_email"],
                    "Empty Form Action": features["SFH"]
                }
                
                df_form = pd.DataFrame({
                    'Feature': list(form_features.keys()),
                    'Count': list(form_features.values())
                })
                
                fig_form = px.pie(df_form, names='Feature', values='Count', 
                                 title='Form Analysis', hole=0.4,
                                 color_discrete_sequence=px.colors.sequential.Plasma)
                st.plotly_chart(fig_form, use_container_width=True)
            else:
                st.warning("Could not retrieve page content for analysis.")
        
        with tab3:
            st.subheader("Security Features")
            
            security_features = {
                "SSL Final State": "Yes" if features["SSLfinal_State"] == 1 else "No",
                "SSL Issuer": features["ssl_issuer"] if features["ssl_issuer"] else "N/A",
                "SSL Validity Days": features["ssl_validity_days"] if features["ssl_validity_days"] > 0 else "N/A",
                "DNS Record Exists": "Yes" if features["DNSRecord"] == 1 else "No",
                "MX Record Exists": "Yes" if features["dns_mx_record"] == 1 else "No",
                "DNS TTL": features["dns_ttl"] if features["dns_ttl"] > 0 else "N/A",
                "Web Traffic": features["web_traffic"] if features["web_traffic"] > 0 else "N/A",
                "Google Index": "Yes" if features["Google_Index"] == 1 else "No",
                "Domain in Top 1M": "Yes" if features["domain_in_top_1m"] == 1 else "No",
                "Statistical Report": "Blacklisted" if features["Statistical_report"] == 1 else "Not Blacklisted",
                "Whois Country": features["whois_country"] if features["whois_country"] else "N/A",
                "Abnormal URL": "Yes" if features["Abnormal_URL"] == 1 else "No",
                "Redirects": "Yes" if features["Redirect"] == 1 else "No",
                "Redirect Chain Length": features["redirect_chain_length"],
                "HTTP Response Code": features["http_response_code"]
            }
            
            df_security = pd.DataFrame(list(security_features.items()), columns=["Feature", "Value"])
            st.table(df_security)
            
            # Create radar chart for key security indicators
            security_indicators = {
                "SSL Enabled": features["SSLfinal_State"],
                "DNS Record": features["DNSRecord"],
                "MX Record": features["dns_mx_record"],
                "Google Indexed": features["Google_Index"],
                "Not Blacklisted": 1 - features["Statistical_report"],
                "No Redirects": 1 - features["Redirect"],
                "Not Abnormal": 1 - features["Abnormal_URL"]
            }
            
            df_radar = pd.DataFrame(dict(
                r=list(security_indicators.values()),
                theta=list(security_indicators.keys())
            ))
            
            fig = px.line_polar(df_radar, r='r', theta='theta', line_close=True,
                               range_r=[0,1], title="Security Indicators (1=Good)")
            st.plotly_chart(fig, use_container_width=True)
        
        with tab4:
            st.subheader("Advanced Features & Raw Data")
            
            # Risk score calculation (simplified)
            risk_features = [
                features["having_IP_Address"], 
                features["Shortening_Service"],
                features["having_At_Symbol"],
                features["double_slash_redirecting"],
                features["Prefix_Suffix"],
                features["Submitting_to_email"],
                features["Abnormal_URL"],
                features["Redirect"],
                features["RightClick"],
                features["popUpWidnow"],
                features["Iframe"],
                1 - features["SSLfinal_State"],  # Invert so 1 means risk
                1 - features["DNSRecord"],       # Invert so 1 means risk
                1 - features["Google_Index"],    # Invert so 1 means risk
                features["Statistical_report"],
                features["js_obfuscation_score"] / 10  # Normalize to 0-1
            ]
            
            risk_score = sum(risk_features) / len(risk_features) * 100
            
            # Risk level determination
            risk_level = "Low"
            color = "normal"
            if risk_score > 30:
                risk_level = "Medium"
                color = "inverse"
            if risk_score > 60:
                risk_level = "High" 
                color = "off"
                
            # Display risk score
            st.metric("Phishing Risk Score", f"{risk_score:.1f}%", delta=risk_level, delta_color=color)
            
            # Progress bar for risk score
            st.progress(risk_score/100)
            
            # Show all raw features
            st.subheader("All Extracted Features")
            
            # Convert features to DataFrame for display
            df_all = pd.DataFrame(list(features.items()), columns=["Feature", "Value"])
            st.dataframe(df_all, use_container_width=True)
            
    except Exception as e:
        st.error(f"Error analyzing URL: {e}")
        st.write("Please check the URL and try again.")
    finally:
        # Always clear the progress bar when done
        progress_bar.empty()

# Add some helpful information at the bottom
st.divider()
st.caption("""
Note: This tool provides an analysis based on URL features and does not guarantee 100% accuracy in phishing detection.
Always exercise caution when visiting unknown websites.
""")