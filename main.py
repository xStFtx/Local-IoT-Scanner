import os
import argparse
import socket
import logging
from scapy.all import ARP, Ether, srp, conf
import platform
from mac_vendor_lookup import MacLookup
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
mac_lookup = MacLookup()
detected_macs = set()

def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def get_vendor(mac):
    if mac in detected_macs:
        return mac_lookup._cache.get(mac, "Unknown")
    try:
        vendor = mac_lookup.lookup(mac)
        detected_macs.add(mac)
        return vendor
    except Exception:
        return "Unknown"

def scan_ip(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    result = srp(packet, timeout=2, verbose=0)[0]

    devices_list = []
    for sent, received in result:
        try:
            hostname = socket.getfqdn(received.psrc)
        except UnicodeError:
            hostname = "Unknown"
        devices_list.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': hostname,
            'vendor': get_vendor(received.hwsrc)
        })
    return devices_list

def scan_network(ip_range, max_workers):
    ips = list(conf.route.route(dst=ip_range)[2])
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        devices_list = list(tqdm(executor.map(scan_ip, ips), total=len(ips), desc="Scanning", ncols=100))

    devices = []
    for sublist in devices_list:
        devices.extend(sublist)
    return devices

def display_devices(devices_list, quiet=False):
    max_hostname_len = max((len(device['hostname']) for device in devices_list), default=15)
    max_vendor_len = max((len(device['vendor']) for device in devices_list), default=10)
    header_len = max_hostname_len + max_vendor_len + 40

    if not quiet:
        print("\nDevices detected:")
        print(f"{'IP Address':<15}{'MAC Address':<20}{'Hostname':<{max_hostname_len}}{'Vendor':<{max_vendor_len}}")
        print('-' * header_len)
        for device in devices_list:
            print(f"{device['ip']:<15}{device['mac']:<20}{device['hostname']:<{max_hostname_len}}{device['vendor']:<{max_vendor_len}}")
        print(f"\nTotal Devices Detected: {len(devices_list)}")

def save_to_csv(devices_list, filename):
    with open(filename, 'w') as f:
        f.write("IP Address,MAC Address,Hostname,Vendor\n")
        for device in devices_list:
            f.write(f"{device['ip']},{device['mac']},{device['hostname']},{device['vendor']}\n")

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("-r", "--range", help="Specify IP range in CIDR format. Default: 192.168.1.1/24", default=None)
    parser.add_argument("-s", "--save", help="Save results to a CSV file.", action="store_true")
    parser.add_argument("-q", "--quiet", help="Quiet mode, suppress standard output.", action="store_true")
    parser.add_argument("-o", "--output", help="Specify output filename. Default: scan_results.csv", default="scan_results.csv")
    parser.add_argument("-w", "--workers", type=int, help="Number of concurrent workers. Default: 50", default=50)
    
    args = parser.parse_args()

    if not args.range:
        clear_screen()
        args.range = input("Enter IP range to scan (e.g. 192.168.1.1/24): ")

    return args

def main():
    try:
        args = get_arguments()
        clear_screen()
        logging.info("Scanning local network for devices...")
        devices_list = scan_network(args.range, args.workers)

        display_devices(devices_list, args.quiet)

        if args.save:
            save_to_csv(devices_list, args.output)
            logging.info(f"Results saved to {args.output}")

    except PermissionError:
        logging.error("Permission denied. Please run the script as root or with sudo permissions.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
