import re
import argparse

def parse_syslog(file_path, target_ip):
    flows = set()
    ip_pattern = re.compile(
        r'source-address="(?P<src_ip>[^"]+)" source-port="(?P<src_port>\\d+)" '
        r'destination-address="(?P<dst_ip>[^"]+)" destination-port="(?P<dst_port>\\d+)"[^"]*'
        r'protocol-id="(?P<proto_id>\\d+)"'
    )

    with open(file_path, 'r') as f:
        for line in f:
            match = ip_pattern.search(line)
            if match:
                src_ip = match.group('src_ip')
                src_port = match.group('src_port')
                dst_ip = match.group('dst_ip')
                dst_port = match.group('dst_port')
                proto_id = match.group('proto_id')

                if target_ip in [src_ip, dst_ip]:
                    protocol = 'TCP' if proto_id == '6' else 'UDP' if proto_id == '17' else f'ID-{proto_id}'
                    flows.add((src_ip, src_port, dst_ip, dst_port, protocol))

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
