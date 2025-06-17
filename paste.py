import re
import socket
import ssl
import whois
import requests
import math
import urllib.parse
import dns.resolver
import time
import ipaddress
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from collections import Counter

def is_ipv4(address):
    """Check if a string is a valid IPv4 address"""
    try:
        ipaddress.IPv4Address(address)
        return True
    except:
        return False

def is_ipv6(address):
    """Check if a string is a valid IPv6 address"""
    try:
        ipaddress.IPv6Address(address)
        return True
    except:
        return False

def is_decimal_ip(address):
    """Check if a string is a decimal representation of an IPv4 address"""
    try:
        n = int(address)
        if n > 0 and n < 4294967296:  # Valid range for IPv4
            return True
        return False
    except:
        return False

def is_hex_ip(address):
    """Check if a string is a hexadecimal representation of an IPv4 address"""
    if not address.lower().startswith('0x'):
        return False
    try:
        n = int(address, 16)
        if n > 0 and n < 4294967296:  # Valid range for IPv4
            return True
        return False
    except:
        return False

def is_octal_ip(address):
    """Check if a string might be an octal representation of an IPv4 address"""
    parts = address.split('.')
    for part in parts:
        if part.startswith('0') and len(part) > 1 and part.isdigit():
            return True
    return False

def check_ip_in_domain(domain):
    """
    Comprehensive check to detect if a domain is an IP address in any format
    
    Args:
        domain (str): The domain to check
        
    Returns:
        bool: True if the domain is any form of IP address
    """
    # Handle IPv6 in brackets
    if domain.startswith('[') and ']' in domain:
        ipv6_match = re.match(r'\[(.*?)\]', domain)
        if ipv6_match:
            ipv6_addr = ipv6_match.group(1)
            return is_ipv6(ipv6_addr)
    
    # Check standard IPv4
    if is_ipv4(domain):
        return True
    
    # Check decimal IP (like 3232235521 for 192.168.0.1)
    if domain.isdigit() and is_decimal_ip(domain):
        return True
    
    # Check hexadecimal IP (like 0xC0A80001 for 192.168.0.1)
    if is_hex_ip(domain):
        return True
    
    # Check octal IP format (like 0177.0.0.01 for 127.0.0.1)
    if is_octal_ip(domain):
        return True
    
    # Check mixed format (like 0xFF.0xFF.0xFF.0xFF)
    parts = domain.split('.')
    if len(parts) == 4:
        try:
            for part in parts:
                if part.lower().startswith('0x'):
                    int(part, 16)
                elif part.startswith('0') and len(part) > 1 and part.isdigit():
                    int(part, 8)
                else:
                    int(part)
            return True
        except:
            pass
    
    return False

def extract_url_features(url):
    """
    Extract phishing detection features from a given URL
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary containing all extracted features
    """
    features = {}
    
    # Parse the URL
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:  # Handle case where URL might not have proper format
            if url.startswith('http'):
                domain = url.split('//')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
        
        # Handle port if present
        if ':' in domain and not (domain.startswith('[') and ']' in domain):
            domain = domain.split(':')[0]
        
        # Handle credentials if present
        if '@' in domain:
            domain = domain.split('@')[-1]
    except:
        domain = ""
    
    # 1. having_IP_Address
    try:
        features["having_IP_Address"] = 1 if check_ip_in_domain(domain) else 0
    except:
        features["having_IP_Address"] = 0
    
    # 2. URL_Length
    features["URL_Length"] = len(url)
    
    # 3. Shortening_Service
    shortening_services = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", 
                          "shorte.st", "go2l.ink", "x.co", "ow.ly", "w.wiki",
                          "tr.im", "cli.gs", "qr.net", "cutt.ly", "tiny.cc"]
    features["Shortening_Service"] = 1 if any(service in domain.lower() for service in shortening_services) else 0
    
    # 4. having_At_Symbol
    features["having_At_Symbol"] = 1 if '@' in url else 0
    
    # 5. double_slash_redirecting
    pattern = r"[^:]//"
    features["double_slash_redirecting"] = 1 if re.search(pattern, url) else 0
    
    # 6. Prefix_Suffix
    features["Prefix_Suffix"] = 1 if '-' in domain else 0
    
    # 7. having_Sub_Domain
    if domain:
        # Count dots in domain (excluding the TLD dot)
        subdomains = domain.split('.')
        if len(subdomains) > 2:
            features["having_Sub_Domain"] = len(subdomains) - 2
        else:
            features["having_Sub_Domain"] = 0
    else:
        features["having_Sub_Domain"] = 0
    
    # 8. SSLfinal_State
    try:
        if parsed_url.scheme == 'https':
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    features["SSLfinal_State"] = 1
        else:
            features["SSLfinal_State"] = 0
    except:
        features["SSLfinal_State"] = 0
    
    # 9. Domain_registeration_length
    try:
        w = whois.whois(domain)
        if w.expiration_date:
            if isinstance(w.expiration_date, list):
                expiration_date = w.expiration_date[0]
            else:
                expiration_date = w.expiration_date
            
            days_to_expire = (expiration_date - datetime.now()).days
            features["Domain_registeration_length"] = max(0, days_to_expire)
        else:
            features["Domain_registeration_length"] = 0
    except:
        features["Domain_registeration_length"] = 0
    
    # For features that require HTML content
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
    except:
        content = ""
        soup = None
    
    # 10. Favicon
    features["Favicon"] = 0
    if soup:
        favicon_links = soup.find_all('link', rel='icon') or soup.find_all('link', rel='shortcut icon')
        if favicon_links:
            for link in favicon_links:
                favicon_url = link.get('href', '')
                if favicon_url:
                    if favicon_url.startswith('http'):
                        favicon_domain = urlparse(favicon_url).netloc
                        if domain and favicon_domain and domain in favicon_domain:
                            features["Favicon"] = 1
                            break
                    else:
                        # Relative URL, so from same domain
                        features["Favicon"] = 1
                        break
    
    # 11. port
    non_standard_ports = [str(p) for p in range(1, 65536) if p not in [80, 443]]
    port_pattern = rf":{{'({'|'.join(non_standard_ports)}')}}"
    features["port"] = 1 if re.search(port_pattern, url) else 0
    
    # 12. HTTPS_token
    features["HTTPS_token"] = 1 if 'https' in domain.lower() else 0
    
    # 13. Request_URL
    features["Request_URL"] = 0.0
    if soup:
        total_objects = 0
        external_objects = 0
        
        # Check images
        for img in soup.find_all('img', src=True):
            total_objects += 1
            src = img['src']
            if src.startswith('http') and domain not in urlparse(src).netloc:
                external_objects += 1
        
        # Check scripts
        for script in soup.find_all('script', src=True):
            total_objects += 1
            src = script['src']
            if src.startswith('http') and domain not in urlparse(src).netloc:
                external_objects += 1
        
        if total_objects > 0:
            features["Request_URL"] = external_objects / total_objects
    
    # 14. URL_of_Anchor
    features["URL_of_Anchor"] = 0.0
    if soup:
        total_anchors = len(soup.find_all('a', href=True))
        external_anchors = 0
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href != "#" and not href.startswith('/'):
                if href.startswith('http') and domain not in urlparse(href).netloc:
                    external_anchors += 1
                elif href.startswith('mailto:'):
                    external_anchors += 1
                    
        if total_anchors > 0:
            features["URL_of_Anchor"] = external_anchors / total_anchors
    
    # 15. Links_in_tags
    features["Links_in_tags"] = 0.0
    if soup:
        total_tags = len(soup.find_all())
        meta_script_link_tags = len(soup.find_all(['meta', 'script', 'link']))
        
        if total_tags > 0:
            features["Links_in_tags"] = meta_script_link_tags / total_tags
    
    # 16. SFH (Server Form Handler)
    features["SFH"] = 0
    if soup:
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action == "" or action == "about:blank":
                features["SFH"] = 1
                break
    
    # 17. Submitting_to_email
    features["Submitting_to_email"] = 0
    if soup:
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action.startswith('mailto:'):
                features["Submitting_to_email"] = 1
                break
    
    # 18. Abnormal_URL
    features["Abnormal_URL"] = 0
    try:
        w = whois.whois(domain)
        if w.domain_name:
            if isinstance(w.domain_name, list):
                domain_name = w.domain_name[0].lower()
            else:
                domain_name = w.domain_name.lower()
            
            if domain_name not in domain.lower():
                features["Abnormal_URL"] = 1
    except:
        features["Abnormal_URL"] = 0
    
    # 19. Redirect
    features["Redirect"] = 0
    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        if response.status_code >= 300 and response.status_code < 400:
            features["Redirect"] = 1
    except:
        features["Redirect"] = 0
    
    # 20. on_mouseover
    features["on_mouseover"] = 0
    if soup:
        elements_with_onmouseover = soup.find_all(onmouseover=True)
        for element in elements_with_onmouseover:
            onmouseover_attr = element.get('onmouseover', '')
            if 'window.status' in onmouseover_attr:
                features["on_mouseover"] = 1
                break
    
    # 21. RightClick
    features["RightClick"] = 0
    if soup:
        if soup.find_all(oncontextmenu="return false") or "oncontextmenu=\"return false\"" in content:
            features["RightClick"] = 1
    
    # 22. popUpWidnow
    features["popUpWidnow"] = 0
    if soup:
        if "window.open" in content:
            features["popUpWidnow"] = 1
    
    # 23. Iframe
    features["Iframe"] = 0
    if soup and soup.find_all('iframe'):
        features["Iframe"] = 1
    
    # 24. age_of_domain
    features["age_of_domain"] = 0
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            age_days = (datetime.now() - creation_date).days
            features["age_of_domain"] = max(0, age_days)
    except:
        features["age_of_domain"] = 0
    
    # 25. DNSRecord
    features["DNSRecord"] = 0
    try:
        dns.resolver.resolve(domain, 'A')
        features["DNSRecord"] = 1
    except:
        features["DNSRecord"] = 0
    
    # 26. web_traffic
    features["web_traffic"] = 0
    # This would typically use a service like Alexa API, but we'll use a placeholder
    try:
        response = requests.get(f"https://data.alexa.com/data?cli=10&url={domain}", timeout=5)
        if response.status_code == 200:
            rank_match = re.search(r'<POPULARITY URL="[^"]+" TEXT="(\d+)"/>', response.text)
            if rank_match:
                features["web_traffic"] = int(rank_match.group(1))
            else:
                features["web_traffic"] = 0
    except:
        features["web_traffic"] = 0
    
    # 27. Page_Rank
    features["Page_Rank"] = 0.0
    # PageRank is no longer publicly available, so this is a placeholder
    
    # 28. Google_Index
    features["Google_Index"] = 0
    try:
        search_url = f"https://www.google.com/search?q=site:{domain}"
        response = requests.get(search_url, headers=headers, timeout=5)
        if "did not match any documents" not in response.text:
            features["Google_Index"] = 1
    except:
        features["Google_Index"] = 0
    
    # 29. Links_pointing_to_page
    features["Links_pointing_to_page"] = 0
    if soup:
        features["Links_pointing_to_page"] = len(soup.find_all('a', href=True))
    
    # 30. Statistical_report
    features["Statistical_report"] = 0
    # This would typically check against blacklists, but we'll use a placeholder
    blacklisted_domains = ["phishing.org", "malware.org", "scam.com"]
    if any(bad_domain in domain for bad_domain in blacklisted_domains):
        features["Statistical_report"] = 1
    
    # 31. Result (0=safe, 1=suspicious, 2=malicious)
    # This would be calculated based on the other features, but we'll leave it as 0 for now
    features["Result"] = 0
    
    # 32. entropy_of_url
    def calculate_entropy(string):
        counter = Counter(string)
        entropy = 0
        for count in counter.values():
            probability = count / len(string)
            entropy += -probability * math.log2(probability)
        return entropy
    
    features["entropy_of_url"] = calculate_entropy(url)
    
    # 33. ratio_digits
    digit_count = sum(c.isdigit() for c in url)
    features["ratio_digits"] = digit_count / len(url) if len(url) > 0 else 0
    
    # 34. contains_login_keywords
    login_keywords = ["login", "verify", "password", "secure", "account", "signin", "banking"]
    features["contains_login_keywords"] = 1 if any(keyword in url.lower() for keyword in login_keywords) else 0
    
    # 35. url_is_encoded
    features["url_is_encoded"] = 1 if '%' in url else 0
    
    # 36. domain_in_top_1m
    features["domain_in_top_1m"] = 0
    # This would typically check against Alexa/Tranco list, but we'll use a placeholder
    
    # 37. whois_country
    features["whois_country"] = ""
    try:
        w = whois.whois(domain)
        features["whois_country"] = w.country if hasattr(w, 'country') else ""
    except:
        features["whois_country"] = ""
    
    # 38. ssl_issuer
    features["ssl_issuer"] = ""
    try:
        if parsed_url.scheme == 'https':
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    features["ssl_issuer"] = issuer.get('organizationName', "")
    except:
        features["ssl_issuer"] = ""
    
    # 39. html_length
    features["html_length"] = len(content) if content else 0
    
    # 40. js_obfuscation_score
    features["js_obfuscation_score"] = 0
    if content:
        # Simple heuristics for obfuscation detection
        obfuscation_indicators = [
            "eval(", "fromCharCode", "String.fromCharCode", "unescape(", 
            "escape(", "parseInt(", ".substr(", ".substring(",
            "\\x", "\\u00"
        ]
        
        score = 0
        for indicator in obfuscation_indicators:
            if indicator in content:
                score += 1
        
        features["js_obfuscation_score"] = min(10, score)
    
    # 41. external_script_count
    features["external_script_count"] = 0
    if soup:
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith('http') and domain not in urlparse(src).netloc:
                features["external_script_count"] += 1
    
    # 42. js_eval_function_count
    features["js_eval_function_count"] = 0
    if content:
        js_dangerous_functions = ["eval(", "setTimeout(", "setInterval(", "document.write("]
        for func in js_dangerous_functions:
            features["js_eval_function_count"] += content.count(func)
    
    # 43. redirect_chain_length
    features["redirect_chain_length"] = 0
    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        features["redirect_chain_length"] = len(response.history)
    except:
        features["redirect_chain_length"] = 0
    
    # 44. dns_mx_record
    features["dns_mx_record"] = 0
    try:
        dns.resolver.resolve(domain, 'MX')
        features["dns_mx_record"] = 1
    except:
        features["dns_mx_record"] = 0
    
    # 45. screenshot_hash_match
    features["screenshot_hash_match"] = 0
    # This would require an actual screenshot and a database of phishing templates
    
    # 46. http_response_code
    features["http_response_code"] = 0
    try:
        response = requests.get(url, headers=headers, timeout=5)
        features["http_response_code"] = response.status_code
    except:
        features["http_response_code"] = 0
    
    # 47. title_tag_keywords
    features["title_tag_keywords"] = 0
    if soup:
        title = soup.find('title')
        if title:
            suspicious_words = ["login", "verify", "verification", "account", "secure", "security", 
                              "update", "confirm", "password", "sign in", "authenticate"]
            if any(word in title.text.lower() for word in suspicious_words):
                features["title_tag_keywords"] = 1
    
    # 48. page_text_lang_match_domain
    features["page_text_lang_match_domain"] = 0
    # This would typically use a language detection library
    # For simplicity, we're not implementing this fully
    
    # 49. form_count
    features["form_count"] = 0
    if soup:
        features["form_count"] = len(soup.find_all('form'))
    
    # 50. form_action_matches_domain
    features["form_action_matches_domain"] = 0
    if soup and domain:
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action.startswith('http'):
                action_domain = urlparse(action).netloc
                if domain in action_domain:
                    features["form_action_matches_domain"] = 1
                    break
            else:
                # Relative URL, so from same domain
                features["form_action_matches_domain"] = 1
                break
    
    # 51. ssl_validity_days
    features["ssl_validity_days"] = 0
    try:
        if parsed_url.scheme == 'https':
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    features["ssl_validity_days"] = (not_after - datetime.now()).days
    except:
        features["ssl_validity_days"] = 0
    
    # 52. dns_ttl
    features["dns_ttl"] = 0
    try:
        import subprocess
        output = subprocess.check_output(['dig', domain, '+noall', '+answer'], universal_newlines=True)
        ttl_match = re.search(r'\s+(\d+)\s+IN\s+', output)
        if ttl_match:
            features["dns_ttl"] = int(ttl_match.group(1))
    except:
        features["dns_ttl"] = 0
    
    return features

def main():
    url = input("Enter a URL to analyze: ")
    
    try:
        # Add http:// prefix if missing
        if not url.startswith('http'):
            url = 'http://' + url
            
        print(f"\nAnalyzing URL: {url}\n")
        start_time = time.time()
        
        features = extract_url_features(url)
        
        print("URL Feature Extraction Complete")
        print(f"Time taken: {time.time() - start_time:.2f} seconds\n")
        
        # Print features in a readable format
        for feature, value in features.items():
            print(f"{feature}: {value}")
            
    except Exception as e:
        print(f"Error analyzing URL: {e}")

if __name__ == "__main__":
    main() 