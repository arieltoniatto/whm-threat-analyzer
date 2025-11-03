import os
import sys
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from collections import Counter
import numpy as np

class IPThreatAnalyzer:
    def __init__(self, json_file):
        """Initialize the analyzer with a JSON file."""
        self.json_file = json_file
        self.data = self.load_data()
        self.df = self.create_dataframe()
    
    def load_data(self):
        """Load JSON data from file."""
        with open(self.json_file, 'r') as f:
            file = json.load(f)

            return file['ip_analysis']
    
    def create_dataframe(self):
        """Convert nested JSON to a flat pandas DataFrame."""
        records = []
       
        for ip, details in self.data.items():
            record = {
                'ip': ip,
                'timestamp': details.get('timestamp'),
                # IPAPI data
                'country': details.get('ipapi', {}).get('country'),
                'country_code': details.get('ipapi', {}).get('country_code'),
                'region': details.get('ipapi', {}).get('region'),
                'city': details.get('ipapi', {}).get('city'),
                'isp': details.get('ipapi', {}).get('isp'),
                'organization': details.get('ipapi', {}).get('organization'),
                'as_number': details.get('ipapi', {}).get('as_number'),
                'is_proxy': details.get('ipapi', {}).get('is_proxy'),
                'is_hosting': details.get('ipapi', {}).get('is_hosting'),
                'latitude': details.get('ipapi', {}).get('latitude'),
                'longitude': details.get('ipapi', {}).get('longitude'),
                'timezone': details.get('ipapi', {}).get('timezone'),
                # AbuseIPDB data
                'abuse_confidence_score': details.get('abuseipdb', {}).get('abuse_confidence_score'),
                'total_reports': details.get('abuseipdb', {}).get('total_reports'),
                'is_whitelisted': details.get('abuseipdb', {}).get('is_whitelisted'),
                'usage_type': details.get('abuseipdb', {}).get('usage_type'),
                # VirusTotal data
                'vt_malicious': details.get('virustotal', {}).get('malicious'),
                'vt_suspicious': details.get('virustotal', {}).get('suspicious'),
                'vt_harmless': details.get('virustotal', {}).get('harmless'),
                'vt_undetected': details.get('virustotal', {}).get('undetected'),
                'vt_reputation': details.get('virustotal', {}).get('reputation'),
                # Threat assessment
                'threat_score': details.get('threat_assessment', {}).get('threat_score'),
                'risk_level': details.get('threat_assessment', {}).get('risk_level'),
                'risk_factors': ', '.join(details.get('threat_assessment', {}).get('risk_factors', []))
            }
            records.append(record)
        
        df = pd.DataFrame(records)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    
    def get_summary_stats(self):
        """Get summary statistics of the dataset."""
        print("=" * 60)
        print("DATASET SUMMARY")
        print("=" * 60)
        print(f"Total IPs: {len(self.df)}")
        print(f"\nRisk Level Distribution:")
        print(self.df['risk_level'].value_counts())
        print(f"\nCountry Distribution (Top 10):")
        print(self.df['country'].value_counts().head(10))
        print(f"\nProxy IPs: {self.df['is_proxy'].sum()}")
        print(f"Hosting IPs: {self.df['is_hosting'].sum()}")
        print(f"\nAverage Threat Score: {self.df['threat_score'].mean():.2f}")
        print(f"Average Abuse Confidence: {self.df['abuse_confidence_score'].mean():.2f}")
        print("=" * 60)
    
    def filter_by_risk_level(self, risk_level):
        """Filter IPs by risk level (LOW, MEDIUM, HIGH, CRITICAL)."""
        return self.df[self.df['risk_level'] == risk_level.upper()]
    
    def filter_by_country(self, country_code):
        """Filter IPs by country code."""
        return self.df[self.df['country_code'] == country_code.upper()]
    
    def filter_by_threat_score(self, min_score=0, max_score=100):
        """Filter IPs by threat score range."""
        return self.df[(self.df['threat_score'] >= min_score) & 
                       (self.df['threat_score'] <= max_score)]
    
    def get_high_risk_ips(self, threshold=50):
        """Get IPs with threat score above threshold."""
        return self.df[self.df['threat_score'] >= threshold]
    
    def get_proxy_ips(self):
        """Get all proxy IPs."""
        return self.df[self.df['is_proxy'] == True]
    
    def sort_by_threat(self, ascending=False):
        """Sort IPs by threat score."""
        return self.df.sort_values('threat_score', ascending=ascending)
    
    def visualize_risk_distribution(self):
        """Create a pie chart of risk level distribution."""
        plt.figure(figsize=(10, 6))
        risk_counts = self.df['risk_level'].value_counts()
        colors = {'LOW': '#28a745', 'MEDIUM': '#ffc107', 'HIGH': '#fd7e14', 'CRITICAL': '#dc3545'}
        plt.pie(risk_counts.values, labels=risk_counts.index, autopct='%1.1f%%',
                colors=[colors.get(x, '#6c757d') for x in risk_counts.index])
        plt.title('Risk Level Distribution')
        plt.tight_layout()
        plt.show()
    
    def visualize_country_distribution(self, top_n=10):
        """Create a bar chart of top N countries."""
        plt.figure(figsize=(12, 6))
        country_counts = self.df['country'].value_counts().head(top_n)
        sns.barplot(x=country_counts.values, y=country_counts.index, palette='viridis')
        plt.xlabel('Number of IPs')
        plt.ylabel('Country')
        plt.title(f'Top {top_n} Countries by IP Count')
        plt.tight_layout()
        plt.show()
    
    def visualize_threat_score_distribution(self):
        """Create a histogram of threat scores."""
        plt.figure(figsize=(10, 6))
        plt.hist(self.df['threat_score'].dropna(), bins=20, color='coral', edgecolor='black')
        plt.xlabel('Threat Score')
        plt.ylabel('Frequency')
        plt.title('Threat Score Distribution')
        plt.axvline(self.df['threat_score'].mean(), color='red', linestyle='--', 
                    label=f'Mean: {self.df["threat_score"].mean():.2f}')
        plt.legend()
        plt.tight_layout()
        plt.show()
    
    def visualize_virustotal_detection(self):
        """Create a stacked bar chart of VirusTotal detections."""
        plt.figure(figsize=(10, 6))
        vt_data = self.df[['vt_malicious', 'vt_suspicious', 'vt_harmless', 'vt_undetected']].sum()
        colors = ['#dc3545', '#ffc107', '#28a745', '#6c757d']
        plt.bar(range(len(vt_data)), vt_data.values, color=colors)
        plt.xticks(range(len(vt_data)), ['Malicious', 'Suspicious', 'Harmless', 'Undetected'])
        plt.ylabel('Total Count')
        plt.title('VirusTotal Detection Summary')
        plt.tight_layout()
        plt.show()
    
    def visualize_geographic_heatmap(self):
        """Create a scatter plot of IP locations."""
        plt.figure(figsize=(14, 8))
        scatter = plt.scatter(self.df['longitude'], self.df['latitude'], 
                            c=self.df['threat_score'], cmap='RdYlGn_r', 
                            s=100, alpha=0.6, edgecolors='black')
        plt.colorbar(scatter, label='Threat Score')
        plt.xlabel('Longitude')
        plt.ylabel('Latitude')
        plt.title('Geographic Distribution of IPs (colored by Threat Score)')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.show()
    
    def export_to_csv(self, filename='ip_analysis.csv'):
        """Export the DataFrame to CSV and append to bulk_results/ip_analysis.csv."""
        self.df.to_csv(filename, index=False)
        print(f"Data exported to {filename}")

        bulk_reports = 'reports/bulk_reports.csv'
        os.makedirs(os.path.dirname(bulk_reports), exist_ok=True)

        if os.path.exists(bulk_reports):
            existing_df = pd.read_csv(bulk_reports)
            combined_df = pd.concat([existing_df, self.df], ignore_index=True)
        else:
            combined_df = self.df

        combined_df.to_csv(bulk_reports, index=False)
        print(f"Data appended to {bulk_reports}")
    
    def export_filtered_data(self, filtered_df, filename='filtered_ips.json'):
        """Export filtered data back to JSON format."""
        result = {}
        for _, row in filtered_df.iterrows():
            ip = row['ip']
            result[ip] = self.data[ip]
        
        with open(filename, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"Filtered data exported to {filename}")
    
    def search_ip(self, ip_address):
        """Search for a specific IP address."""
        result = self.df[self.df['ip'] == ip_address]
        if not result.empty:
            return result.to_dict('records')[0]
        return None
    
    def get_isp_summary(self):
        """Get summary by ISP."""
        isp_summary = self.df.groupby('isp').agg({
            'ip': 'count',
            'threat_score': 'mean',
            'abuse_confidence_score': 'mean'
        }).round(2)
        isp_summary.columns = ['IP Count', 'Avg Threat Score', 'Avg Abuse Score']
        return isp_summary.sort_values('IP Count', ascending=False)


# Example usage
if __name__ == "__main__":
    # Set domain
    if len(sys.argv) < 2:
        print('Usage: python data_analyzer.py <path/to/filename>')
        sys.exit(1)

    input_path = sys.argv[1]
  
    filename = input_path.split('/')[3].split('_')[2].split('.')[0]
    current_date = datetime.now().strftime("%y-%m-%d")

    # Initialize analyzer
    analyzer = IPThreatAnalyzer(input_path)
    
    # Get summary statistics
    analyzer.get_summary_stats()
    
    # Filter examples
    print("\n--- High Risk IPs (threat score >= 50) ---")
    high_risk = analyzer.get_high_risk_ips(threshold=50)
    print(high_risk[['ip', 'country', 'threat_score', 'risk_level']])
    
    print("\n--- Proxy IPs ---")
    proxies = analyzer.get_proxy_ips()
    print(proxies[['ip', 'country', 'isp', 'threat_score']])
    
    print("\n--- Top 10 ISPs by IP Count ---")
    print(analyzer.get_isp_summary().head(10))
    
    # Visualizations (uncomment to display)
    # analyzer.visualize_risk_distribution()
    # analyzer.visualize_country_distribution(top_n=10)
    # analyzer.visualize_threat_score_distribution()
    # analyzer.visualize_virustotal_detection()
    # analyzer.visualize_geographic_heatmap()
    
    # Export data
    analyzer.export_to_csv(f'reports/{current_date}_report_{filename}.csv')
    
    # Search for specific IP
    # result = analyzer.search_ip('46.183.108.123')
    # if result:
    #     print("\n--- IP Details ---")
    #     for key, value in result.items():
    #         print(f"{key}: {value}")