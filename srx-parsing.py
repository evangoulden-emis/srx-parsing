import re
import argparse
import csv
from collections import defaultdict

def parse_syslog_summary(file_path, target_ip):
    sent_summary = defaultdict(set)
    received_summary = defaultdict(set)

    ip_pattern = re.compile(
        r'source-address="?([\d\.]+)"?\s+source-port="?(\d+)"?\s+'
        r'destination-address="?([\d\.]+)"?\s+destination-port="?(\d+)"?'
    )

    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = ip_pattern.search(line)
                if match:
                    src_ip, src_port, dst_ip, dst_port = match.groups()

                    if target_ip == src_ip:
                        sent_summary[dst_ip].add(dst_port)
                    elif target_ip == dst_ip:
                        received_summary[src_ip].add(dst_port)
    except PermissionError:
        print(f"❌ Permission denied when trying to read: {file_path}")
        return {}, {}
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return {}, {}

    return sent_summary, received_summary

def write_summary_to_csv(sent_summary, received_summary, ip):
    output_file=f'traffic_summary_{ip[0]}.csv'
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Peer IP', 'Direction', 'Destination Port']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for peer_ip, ports in sent_summary.items():
            for port in ports:
                writer.writerow({'Peer IP': peer_ip, 'Direction': 'Sent', 'Destination Port': port})

        for peer_ip, ports in received_summary.items():
            for port in ports:
                writer.writerow({'Peer IP': peer_ip, 'Direction': 'Received', 'Destination Port': port})

    print(f"✅ Traffic summary written to {output_file}")
    
    
def parse_target_file(ips: str) -> list:
    ip_data = []
    with open(ips, 'r') as ips_file:
        data = ips_file.readlines()
        for line in data:
            ip_data.append(line.strip().split(","))
        
    return ip_data   

def main():
    parser = argparse.ArgumentParser(description='Summarize Juniper SRX syslog traffic for a specific IP address and export to CSV.')
    parser.add_argument('file', help='Path to the syslog file')
    # parser.add_argument('ip', help='Target IP address to summarize')
    parser.add_argument('ips', help="Target IP Address file")
    args = parser.parse_args()

    ip_data = parse_target_file(args.ips)
    for ip in ip_data:
        sent_summary, received_summary = parse_syslog_summary(args.file, ip[1])
        write_summary_to_csv(sent_summary, received_summary, ip)

if __name__ == '__main__':
    main()
