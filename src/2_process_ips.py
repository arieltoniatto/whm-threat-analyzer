import json
import sys
import os
from collections import Counter
from datetime import datetime


def process_ips(input_path):
    """
    Process IPs from input file, identify new and repeated IPs.
    
    Args:
        input_path: Path to the input JSON file
    """
    # Extract filename and create output path
    filename = input_path.split('/')[3].split('_')[2].split('.')[0]
    current_date = datetime.now().strftime("%y-%m-%d")
    output_path = f'data/02_intermediate/ip_lists/{current_date}_new-ips_{filename}.json'

    # Load new IPs
    print(f"Loading IPs from: {input_path}")
    with open(input_path, 'r', encoding='utf-8') as f:
        new_ips_data = json.load(f)

    first_key = list(new_ips_data.keys())[0]
    recent_ips_list = new_ips_data[first_key]['ip_list']
    print(f"Found {len(recent_ips_list)} IPs in input file")

    # Load base IP list
    plain_path = 'data/04_persistent/all_ips_master_list.json'
    try:
        with open(plain_path, 'r', encoding='utf-8') as g:
            ip_base = json.load(g)
    except (FileNotFoundError, json.JSONDecodeError):
        ip_base = {'ip_list': []}
        print("Master list not found, creating new one")

    scanned_ips = ip_base['ip_list']

    # Check repeated IPs
    same_ips = [ip for ip in recent_ips_list if ip in scanned_ips]
    if same_ips:
        print(f'{len(same_ips)} repeated IPs found!')
        print(f'Same ips: {same_ips}')

        all_ips = recent_ips_list + scanned_ips
        count_ips = Counter(all_ips)
        repeated_info = {ip: count_ips[ip] for ip in same_ips}

        file_path = 'data/04_persistent/known_ips.json'
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        try:
            with open(file_path, 'r', encoding='utf-8') as j:
                existing_data = json.load(j)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_data = {}

        for ip, count in repeated_info.items():
            existing_data[ip] = existing_data.get(ip, 0) + count

        with open(file_path, 'w', encoding='utf-8') as k:
            json.dump(existing_data, k, ensure_ascii=False, indent=2)

        print(f"Repeated IPs saved in {file_path}")
    else:
        print("No IP was repeated.")

    # Check for new IPs and update main ips
    filtered_new_ips = [ip for ip in recent_ips_list if ip not in scanned_ips]
    if filtered_new_ips:
        print(f'{len(filtered_new_ips)} new IPs found!')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        ips_obj = {
            'ip_list': filtered_new_ips
        }

        with open(output_path, 'w', encoding='utf-8') as h:
            json.dump(ips_obj, h, ensure_ascii=False, indent=2)

        print(f'Saved in: {output_path}')

        # Update main list
        ip_base['ip_list'].extend(ip for ip in filtered_new_ips if ip not in ip_base['ip_list'])
        with open(plain_path, 'w', encoding='utf-8') as i:
            json.dump(ip_base, i, ensure_ascii=False, indent=2)
        
        print(f"Master list updated with {len(filtered_new_ips)} new IPs")
    else:
        print("No new IPs to process")
        # Still create output file with empty list for pipeline continuity
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as h:
            json.dump({'ip_list': []}, h, ensure_ascii=False, indent=2)
        print(f'Empty IP list saved in: {output_path}')

    return output_path


if __name__ == "__main__":
    # Input JSON file (from previous script)
    if len(sys.argv) < 2:
        print('Usage: python 2_process_ips.py <path/to/filename>')
        sys.exit(1)
    
    input_path = sys.argv[1]
    
    try:
        output_file = process_ips(input_path)
        print(f"\n✓ Script 2 completed successfully")
        print(f"Output: {output_file}")
    except Exception as e:
        print(f"\n✗ Error in script 2: {str(e)}")
        sys.exit(1)