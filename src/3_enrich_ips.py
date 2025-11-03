import os
import sys
import json
import requests
import time
from dotenv import load_dotenv
from datetime import datetime
from collections import defaultdict

class IPReputationChecker:
    """
    Checks IP reputation across multiple threat intelligence services.
    """
    
    def __init__(self, abuseipdb_api_key=None, virustotal_api_key=None):
        """
        Initialize with API keys.
        
        Args:
            abuseipdb_api_key: API key for AbuseIPDB
            virustotal_api_key: API key for VirusTotal
        """
        self.abuseipdb_key = abuseipdb_api_key
        self.virustotal_key = virustotal_api_key
        self.results = defaultdict(dict)
    
    def check_abuseipdb(self, ip_address):
        """
        Check IP reputation on AbuseIPDB.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with abuse data
        """
        if not self.abuseipdb_key:
            return {"error": "No API key provided"}
        
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': self.abuseipdb_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if 'data' in data:
                return {
                    'ip': ip_address,
                    'abuse_confidence_score': data['data'].get('abuseConfidenceScore', 0),
                    'total_reports': data['data'].get('totalReports', 0),
                    'country': data['data'].get('countryCode', 'Unknown'),
                    'isp': data['data'].get('isp', 'Unknown'),
                    'is_whitelisted': data['data'].get('isWhitelisted', False),
                    'usage_type': data['data'].get('usageType', 'Unknown'),
                    'status': 'checked'
                }
            return {"error": "No data returned", "status": "error"}
        
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "status": "error"}
    
    def check_virustotal(self, ip_address):
        """
        Check IP reputation on VirusTotal.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with threat data
        """
        if not self.virustotal_key:
            return {"error": "No API key provided"}
        
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {
            'x-apikey': self.virustotal_key
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if 'data' in data:
                attributes = data['data'].get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    'ip': ip_address,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'country': attributes.get('country', 'Unknown'),
                    'asn': attributes.get('asn', 'Unknown'),
                    'as_owner': attributes.get('as_owner', 'Unknown'),
                    'reputation': attributes.get('reputation', 0),
                    'status': 'checked'
                }
            return {"error": "No data returned", "status": "error"}
        
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "status": "error"}
    
    def check_ipapi(self, ip_address):
        """
        Check IP geolocation and ISP info using ip-api.com (free, no key needed).
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with geolocation data
        """
        url = f'http://ip-api.com/json/{ip_address}'
        params = {
            'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query'
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                return {
                    'ip': ip_address,
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'organization': data.get('org', 'Unknown'),
                    'as_number': data.get('as', 'Unknown'),
                    'is_proxy': data.get('proxy', False),
                    'is_hosting': data.get('hosting', False),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0),
                    'timezone': data.get('timezone', 'Unknown'),
                    'status': 'checked'
                }
            return {"error": data.get('message', 'Unknown error'), "status": "error"}
        
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "status": "error"}
    
    def analyze_ip(self, ip_address, rate_limit_delay=1):
        """
        Analyze an IP across all services.
        
        Args:
            ip_address: IP address to analyze
            rate_limit_delay: Delay between API calls in seconds
            
        Returns:
            Dictionary with combined results
        """
        print(f"Analyzing IP: {ip_address}")
        
        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check ip-api (free service, check first)
        print(f"  Checking ip-api.com...")
        results['ipapi'] = self.check_ipapi(ip_address)
        time.sleep(rate_limit_delay)
        
        # Check AbuseIPDB
        if self.abuseipdb_key:
            print(f"  Checking AbuseIPDB...")
            results['abuseipdb'] = self.check_abuseipdb(ip_address)
            time.sleep(rate_limit_delay)
        else:
            results['abuseipdb'] = {"status": "skipped", "error": "No API key"}
        
        # Check VirusTotal
        if self.virustotal_key:
            print(f"  Checking VirusTotal...")
            results['virustotal'] = self.check_virustotal(ip_address)
            time.sleep(rate_limit_delay)
        else:
            results['virustotal'] = {"status": "skipped", "error": "No API key"}
        
        return results
    
    def calculate_threat_score(self, ip_results):
        """
        Calculate overall threat score based on all services.
        
        Args:
            ip_results: Results dictionary for an IP
            
        Returns:
            Threat score (0-100) and risk level
        """
        score = 0
        factors = []
        
        # AbuseIPDB scoring
        if ip_results.get('abuseipdb', {}).get('status') == 'checked':
            abuse_score = ip_results['abuseipdb'].get('abuse_confidence_score', 0)
            score += abuse_score * 0.4  # 40% weight
            if abuse_score > 0:
                factors.append(f"AbuseIPDB score: {abuse_score}")
        
        # VirusTotal scoring
        if ip_results.get('virustotal', {}).get('status') == 'checked':
            malicious = ip_results['virustotal'].get('malicious', 0)
            suspicious = ip_results['virustotal'].get('suspicious', 0)
            vt_score = min(100, (malicious * 10) + (suspicious * 5))
            score += vt_score * 0.4  # 40% weight
            if malicious > 0 or suspicious > 0:
                factors.append(f"VirusTotal detections: {malicious} malicious, {suspicious} suspicious")
        
        # IP-API scoring (proxy/hosting)
        if ip_results.get('ipapi', {}).get('status') == 'checked':
            is_proxy = ip_results['ipapi'].get('is_proxy', False)
            is_hosting = ip_results['ipapi'].get('is_hosting', False)
            if is_proxy:
                score += 20 * 0.2  # 20% weight
                factors.append("IP is a proxy")
            if is_hosting:
                score += 10 * 0.2  # 20% weight
                factors.append("IP is hosting/datacenter")
        
        # Determine risk level
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        elif score > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"
        
        return {
            'threat_score': round(score, 2),
            'risk_level': risk_level,
            'risk_factors': factors
        }
    
    def analyze_json_file(self, json_file_path, rate_limit_delay=2):
        """
        Read JSON file and analyze all IPs.
        
        Args:
            json_file_path: Path to JSON file from spam detector
            rate_limit_delay: Delay between IP checks
            
        Returns:
            Dictionary with all analysis results
        """
        print(f"\n{'='*80}")
        print(f"IP REPUTATION ANALYSIS")
        print(f"{'='*80}\n")
        print(f"Reading file: {json_file_path}")
        
        # Read JSON file
        with open(json_file_path, 'r', encoding='utf-8') as f:
            suspicious_accounts = json.load(f)
        
        # Collect all unique IPs
        all_ips = []
        for ips in suspicious_accounts['ip_list']:
            
            all_ips.append(ips)
        
        print(f"Found {len(all_ips)} unique IPs to analyze\n")
        
        # Analyze each IP
        ip_analysis = {}
        for idx, ip in enumerate(all_ips, 1):
            print(f"\n[{idx}/{len(all_ips)}] " + "-"*60)
            results = self.analyze_ip(ip, rate_limit_delay)
            threat_info = self.calculate_threat_score(results)
            results['threat_assessment'] = threat_info
            ip_analysis[ip] = results
        
        return {
            'analysis_date': datetime.now().isoformat(),
            'total_ips_analyzed': len(all_ips),
            'suspicious_accounts': suspicious_accounts,
            'ip_analysis': ip_analysis
        }
    
    def generate_report(self, analysis_results, output_file=None):
        """
        Generate a comprehensive report.
        
        Args:
            analysis_results: Results from analyze_json_file
            output_file: Optional path to save report
        """
        print(f"\n\n{'='*80}")
        print(f"THREAT INTELLIGENCE REPORT")
        print(f"{'='*80}\n")
        
        ip_analysis = analysis_results['ip_analysis']
        
        # Summary statistics
        critical_ips = [ip for ip, data in ip_analysis.items() 
                       if data['threat_assessment']['risk_level'] == 'CRITICAL']
        high_risk_ips = [ip for ip, data in ip_analysis.items() 
                        if data['threat_assessment']['risk_level'] == 'HIGH']
        medium_risk_ips = [ip for ip, data in ip_analysis.items() 
                          if data['threat_assessment']['risk_level'] == 'MEDIUM']
        low_risk_ips = [ip for ip, data in ip_analysis.items() 
                       if data['threat_assessment']['risk_level'] == 'LOW']
        clean_ips = [ip for ip, data in ip_analysis.items() 
                    if data['threat_assessment']['risk_level'] == 'CLEAN']
        
        print(f"Analysis Date: {analysis_results['analysis_date']}")
        print(f"Total IPs Analyzed: {analysis_results['total_ips_analyzed']}\n")
        
        print(f"Risk Distribution:")
        print(f"  🔴 CRITICAL: {len(critical_ips)}")
        print(f"  🟠 HIGH: {len(high_risk_ips)}")
        print(f"  🟡 MEDIUM: {len(medium_risk_ips)}")
        print(f"  🟢 LOW: {len(low_risk_ips)}")
        print(f"  ⚪ CLEAN: {len(clean_ips)}\n")
        
        # Detailed findings
        print(f"{'-'*80}")
        print(f"DETAILED FINDINGS")
        print(f"{'-'*80}\n")
        
        # Sort IPs by threat score
        sorted_ips = sorted(ip_analysis.items(), 
                           key=lambda x: x[1]['threat_assessment']['threat_score'], 
                           reverse=True)
        
        for ip, data in sorted_ips:
            threat = data['threat_assessment']
            
            # Skip clean IPs in detailed report
            if threat['risk_level'] == 'CLEAN':
                continue
            
            risk_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(threat['risk_level'], '⚪')
            
            print(f"{risk_emoji} IP: {ip}")
            print(f"   Risk Level: {threat['risk_level']} (Score: {threat['threat_score']})")
            
            # IP-API info
            if data.get('ipapi', {}).get('status') == 'checked':
                ipapi = data['ipapi']
                print(f"   Location: {ipapi.get('city', 'Unknown')}, {ipapi.get('region', 'Unknown')}, {ipapi.get('country', 'Unknown')}")
                print(f"   ISP: {ipapi.get('isp', 'Unknown')}")
                print(f"   Organization: {ipapi.get('organization', 'Unknown')}")
                if ipapi.get('is_proxy'):
                    print(f"   ⚠️  Proxy/VPN Detected")
                if ipapi.get('is_hosting'):
                    print(f"   ⚠️  Hosting/Datacenter IP")
            
            # AbuseIPDB info
            if data.get('abuseipdb', {}).get('status') == 'checked':
                abuse = data['abuseipdb']
                if abuse.get('total_reports', 0) > 0:
                    print(f"   AbuseIPDB: {abuse.get('total_reports')} reports, {abuse.get('abuse_confidence_score')}% confidence")
            
            # VirusTotal info
            if data.get('virustotal', {}).get('status') == 'checked':
                vt = data['virustotal']
                if vt.get('malicious', 0) > 0 or vt.get('suspicious', 0) > 0:
                    print(f"   VirusTotal: {vt.get('malicious')} malicious, {vt.get('suspicious')} suspicious detections")
            
            # Risk factors
            if threat['risk_factors']:
                print(f"   Risk Factors:")
                for factor in threat['risk_factors']:
                    print(f"      - {factor}")
            
            print()
        
        print(f"{'='*80}\n")
        
        # Save detailed report to file
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, ensure_ascii=False, indent=2)
            print(f"✅ Detailed report saved to: {output_file}\n")


# Main execution
if __name__ == "__main__":
       
    # Input JSON file (from spam detector script)
    if len(sys.argv) < 2:
        print('Usage: python ip_reputation_checker.py <path/to/filename>')
        sys.exit(1)

    input_path = sys.argv[1]
    
    load_dotenv()

    filename = input_path.split('/')[3].split('_')[2].split('.')[0]
    current_date = datetime.now().strftime("%y-%m-%d")
    output_path = f"data/03_enriched/ip_reputation/{current_date}_ip-reputation_{filename}.json"
    
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

    if not ABUSEIPDB_API_KEY or not VIRUSTOTAL_API_KEY:
        raise ValueError(
            "Please set your API Keys in your .env file"
        )
    # Initialize checker
    checker = IPReputationChecker(
        abuseipdb_api_key=ABUSEIPDB_API_KEY,
        virustotal_api_key=VIRUSTOTAL_API_KEY
    )
    
    # Analyze IPs from JSON file
    # Note: Set rate_limit_delay higher if you hit rate limits (free tiers are limited)
    analysis_results = checker.analyze_json_file(input_path, rate_limit_delay=2)
    
    # Generate and save report
    checker.generate_report(analysis_results, output_file=output_path)
    

    print("✅ Analysis complete!")
