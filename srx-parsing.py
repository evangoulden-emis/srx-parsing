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

def write_summary_to_csv(sent_summary, received_summary, target_ip, output_file='traffic_summary.csv'):
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

def main():
    parser = argparse.ArgumentParser(description='Summarize Juniper SRX syslog traffic for a specific IP address and export to CSV.')
    parser.add_argument('file', help='Path to the syslog file')
    parser.add_argument('ip', help='Target IP address to summarize')
    args = parser.parse_args()

    sent_summary, received_summary = parse_syslog_summary(args.file, args.ip)
    write_summary_to_csv(sent_summary, received_summary, args.ip)

if __name__ == '__main__':
    main()
