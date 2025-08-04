import re
import argparse
from collections import defaultdict

def parse_syslog_summary(file_path, target_ip):
    sent_summary = defaultdict(set)
    received_summary = defaultdict(set)

    # Regex to match IPs and ports with flexible formatting
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

def main():
    parser = argparse.ArgumentParser(description='Summarize Juniper SRX syslog traffic for a specific IP address.')
    parser.add_argument('file', help='Path to the syslog file')
    parser.add_argument('ip', help='Target IP address to summarize')
    args = parser.parse_args()

    sent_summary, received_summary = parse_syslog_summary(args.file, args.ip)

    print(f"\n📊 Traffic Summary for IP: {args.ip}\n")

    if sent_summary:
        print("📤 Sent Traffic:")
        for peer_ip, ports in sorted(sent_summary.items()):
            ports_list = ', '.join(sorted(ports))
            print(f"Sent to {peer_ip} on destination ports: {ports_list}")
    else:
        print("No sent traffic found.")

    if received_summary:
        print("\n📥 Received Traffic:")
        for peer_ip, ports in sorted(received_summary.items()):
            ports_list = ', '.join(sorted(ports))
            print(f"Received from {peer_ip} on destination ports: {ports_list}")
    else:
        print("\nNo received traffic found.")

if __name__ == '__main__':
    main()
