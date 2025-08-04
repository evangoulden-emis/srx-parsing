import re
import argparse

def parse_syslog(file_path, target_ip):
    flows = set()

    # Flexible regex to match quoted or unquoted values with variable spacing
    ip_pattern = re.compile(
        r'source-address="?([\d\.]+)"?\s+source-port="?(\d+)"?\s+'
        r'destination-address="?([\d\.]+)"?\s+destination-port="?(\d+)"?.*?'
        r'protocol-id="?(\d+)"?'
    )

    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = ip_pattern.search(line)
                if match:
                    src_ip, src_port, dst_ip, dst_port, proto_id = match.groups()

                    if target_ip in [src_ip, dst_ip]:
                        protocol = 'TCP' if proto_id == '6' else 'UDP' if proto_id == '17' else f'ID-{proto_id}'
                        flows.add((src_ip, src_port, dst_ip, dst_port, protocol))
    except PermissionError:
        print(f"❌ Permission denied when trying to read: {file_path}")
        return []
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return []

    return flows

def main():
    parser = argparse.ArgumentParser(description='Parse Juniper SRX syslog for flows involving a specific IP address.')
    parser.add_argument('file', help='Path to the syslog file')
    parser.add_argument('ip', help='Target IP address to search for')
    args = parser.parse_args()

    results = parse_syslog(args.file, args.ip)

    if results:
        print(f"\n🔍 Flows involving IP: {args.ip}\n")
        for src_ip, src_port, dst_ip, dst_port, protocol in sorted(results):
            print(f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} | Protocol: {protocol}")
    else:
        print(f"No flows found involving IP: {args.ip}")

if __name__ == '__main__':
    main()
