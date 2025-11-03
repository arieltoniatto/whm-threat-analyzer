import re
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict
import sys

def extract_table_data(html_content):
    """
    Extracts relevant data from an HTML email log table.
    
    Args:
        html_content: String containing the table HTML
        
    Returns:
        List of dictionaries with extracted data
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Regex to identify emails
    regex_email_pr = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.pr\.gov\.br'
    regex_email_general = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    extracted_data = []
    
    # Find all table rows
    rows = soup.find_all('tr')
    
    for row in rows:
        record = {}
        
        # Search for event image (success or error)
        img = row.find('img')
        if img and img.get('alt'):
            alt_text = img.get('alt').lower()
            if alt_text in ['success', 'error']:
                record['event'] = alt_text
            else:
                continue  # Ignore if not success or error
        else:
            continue
        
        # Extract sender email address (.pr.gov.br)
        td_email = row.find('td', headers='yui-dt1-th-email')
        if td_email:
            div_email = td_email.find('div')
            if div_email:
                text = div_email.get_text(strip=True)
                match_sender = re.search(regex_email_pr, text)
                if match_sender:
                    record['sender'] = match_sender.group(0)
        
        # Extract sender IP
        td_ip = row.find('td', headers='yui-dt1-th-senderip')
        if td_ip:
            div_ip = td_ip.find('div')
            if div_ip:
                record['sender_ip'] = div_ip.get_text(strip=True)
        
        # Extract recipient
        td_recipient = row.find('td', headers='yui-dt1-th-recipient')
        if td_recipient:
            div_recipient = td_recipient.find('div')
            if div_recipient:
                text = div_recipient.get_text(strip=True)
                match_recipient = re.search(regex_email_general, text)
                if match_recipient:
                    record['recipient'] = match_recipient.group(0)
        
        # Extract sending time
        divs = row.find_all('div')
        for div in divs:
            text = div.get_text(strip=True)
            # Search for date pattern: "20 de out. de 2025 14:04:14"
            if re.search(r'\d{1,2}\s+de\s+\w+\.\s+de\s+\d{4}\s+\d{2}:\d{2}:\d{2}', text):
                record['send_time'] = text
                break
        
        # Extract result (div inside td with headers="yui-dt1-th-message")
        td_message = row.find('td', headers='yui-dt1-th-message')
        if td_message:
            div_result = td_message.find('div')
            if div_result:
                record['result'] = div_result.get_text(strip=True)
        
        # Add only if it has essential data
        if 'sender' in record and 'recipient' in record:
            extracted_data.append(record)
    
    return extracted_data


def detect_spam(data):
    """
    Detects spam patterns based on extracted data.
    
    Detection criteria:
    - High volume of sends from same sender
    - Multiple different recipients
    - High error rate
    - Sends in short time period
    
    Args:
        data: List of dictionaries with email data
        
    Returns:
        Dictionary with analysis of possibly compromised accounts
    """
    # Group by sender address
    sends_by_sender = defaultdict(list)
    
    for record in data:
        sender = record.get('sender')
        if sender:
            sends_by_sender[sender].append(record)
    
    # Analyze each sender
    suspicious_accounts = {}
    
    for sender, sends in sends_by_sender.items():
        total_sends = len(sends)
        unique_recipients = set(e.get('recipient') for e in sends if e.get('recipient'))
        unique_ips = set(e.get('sender_ip') for e in sends if e.get('sender_ip'))
        ip_list = list(unique_ips)  # Convert to list for JSON serialization
        errors = sum(1 for e in sends if e.get('event') == 'error')
        
        # Group sends by time (same timestamp)
        sends_by_time = defaultdict(list)
        for send in sends:
            if send.get('send_time'):
                sends_by_time[send.get('send_time')].append(send)
        
        # Find times with multiple sends
        bulk_sends = {time: len(records) for time, records in sends_by_time.items() if len(records) > 1}
        
        # Collect error messages
        error_messages = set()
        for send in sends:
            if send.get('event') == 'error' and send.get('result'):
                error_messages.add(send.get('result'))
        error_list = list(error_messages)
        
        # Calculate error rate
        error_rate = (errors / total_sends * 100) if total_sends > 0 else 0
        
        # Suspicion criteria (adjustable)
        is_suspicious = False
        reasons = []
        
        if total_sends > 20:  # High send volume
            is_suspicious = True
            reasons.append(f"High volume: {total_sends} sends")
        
        if len(unique_recipients) > 15:  # Many different recipients
            is_suspicious = True
            reasons.append(f"Multiple recipients: {len(unique_recipients)} unique")
        
        if len(unique_ips) > 5:  # Multiple different IPs (possible misuse)
            is_suspicious = True
            reasons.append(f"Multiple sender IPs: {len(unique_ips)} unique")
        
        if bulk_sends:  # Multiple sends at same time
            is_suspicious = True
            total_bulk = sum(bulk_sends.values())
            reasons.append(f"Bulk sends detected: {total_bulk} emails at same timestamps")
        
        if error_rate > 30:  # High error rate
            is_suspicious = True
            reasons.append(f"High error rate: {error_rate:.1f}%")
        
        if is_suspicious:
            suspicious_accounts[sender] = {
                'total_sends': total_sends,
                'unique_recipients': len(unique_recipients),
                'unique_ips': len(unique_ips),
                'ip_list': ip_list,
                'total_errors': errors,
                'error_rate': round(error_rate, 2),
                'error_messages': error_list,
                'bulk_sends': bulk_sends,
                'reasons': reasons,
                'risk_level': 'HIGH' if len(reasons) >= 2 else 'MEDIUM'
            }
    
    return suspicious_accounts


def generate_report(data, suspicious_accounts):
    """
    Generates a detailed analysis report.
    """
    print("=" * 80)
    print("SPAM ANALYSIS REPORT")
    print("=" * 80)
    print(f"\nTotal records analyzed: {len(data)}")
    print(f"Suspicious accounts identified: {len(suspicious_accounts)}\n")
    
    if suspicious_accounts:
        print("-" * 80)
        print("COMPROMISED ACCOUNTS (SUSPICIOUS)")
        print("-" * 80)
        
        for sender, info in sorted(suspicious_accounts.items(), 
                                   key=lambda x: x[1]['total_sends'], 
                                   reverse=True):
            print(f"\n🚨 Email: {sender}")
            print(f"   Risk Level: {info['risk_level']}")
            print(f"   Total Sends: {info['total_sends']}")
            print(f"   Unique Recipients: {info['unique_recipients']}")
            print(f"   Unique IPs: {info['unique_ips']}")
            print(f"   Errors: {info['total_errors']} ({info['error_rate']}%)")
            
            if info.get('bulk_sends'):
                print(f"   Bulk Sends at Same Time:")
                for time, count in sorted(info['bulk_sends'].items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"      - {time}: {count} emails")
                if len(info['bulk_sends']) > 5:
                    print(f"      ... and {len(info['bulk_sends']) - 5} more timestamps")
            
            if info.get('error_messages'):
                print(f"   Error Messages:")
                for error_msg in list(info['error_messages'])[:5]:
                    print(f"      - {error_msg}")
                if len(info['error_messages']) > 5:
                    print(f"      ... and {len(info['error_messages']) - 5} more error types")
            
            print(f"   Suspicion Reasons:")
            for reason in info['reasons']:
                print(f"      - {reason}")
    else:
        print("✅ No suspicious accounts detected.")
    
    print("\n" + "=" * 80)


# Usage example
if __name__ == "__main__":
    
    # Check if an argument was provided
    if len(sys.argv) < 2:
        print("Usage: python spam_data_collector.py <path/to/filename>")
        sys.exit(1)

    htmlfilename = sys.argv[1]


    # To read from a file:
    with open(f'{htmlfilename}', 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Extract data
    data = extract_table_data(html_content)
    
    # Detect spam
    suspicious_accounts = detect_spam(data)
    
    # Generate report
    generate_report(data, suspicious_accounts)
    
    # Export suspicious data (optional)
    if suspicious_accounts:
        print("\n📊 Exporting data for additional analysis...")
        import json
        from datetime import datetime
        
        # Get current date in dd-mm-yy format
        current_date = datetime.now().strftime("%y-%m-%d")
        
        # Extract domain from first suspicious email
        first_email = list(suspicious_accounts.keys())[0]
        account = first_email.split('@')[0]
        domain_tld = first_email.split('@')[1] if '@' in first_email else 'unknown'
        domain = domain_tld.split('.')[0]
        
        # Filename: dd-mm-yy_whm_domain-user.json
        filename = f"{current_date}_whm_{domain}-{account}.json"
        
        with open(f'data/01_processed/whm_extracted/{filename}', 'w', encoding='utf-8') as f:
            json.dump(suspicious_accounts, f, ensure_ascii=False, indent=2)
        print(f"✅ File '{filename}' created.")