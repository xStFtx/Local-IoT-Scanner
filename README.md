# Network Scanner Utility

A powerful network scanner that detects devices on a local network using Scapy, multi-threading, and vendor lookup capabilities. The utility provides detailed information such as IP address, MAC address, hostname, and the device vendor.

## Features

- **Fast Scanning**: Utilizes `ThreadPoolExecutor` for concurrent scanning, leading to quicker results.
- **MAC Vendor Lookup**: Determines the manufacturer of the device from its MAC address.
- **Interactive Mode**: If no arguments are provided, the utility prompts the user for input.
- **Save to CSV**: Option to save the scan results to a CSV file.
- **Quiet Mode**: Suppresses the standard output, useful when saving results directly to a file.
- **Progress Display**: Integrated with `tqdm` to show a progress bar during the scanning process.

## Requirements

- Python 3.x
- Scapy
- `mac_vendor_lookup` library
- `tqdm` library

## Installation

1. Clone the repository or download the utility script.
2. Install required Python libraries:
    ```
    pip install scapy mac_vendor_lookup tqdm
    ```

## Usage

To run the script, navigate to its directory and use:

```
python main.py [arguments]
```


### Arguments

- `-r` or `--range`: Specify IP range in CIDR format. If not provided, will ask for input. E.g. `192.168.1.1/24`.
- `-s` or `--save`: Save results to a CSV file. If not provided, results are displayed in the terminal.
- `-q` or `--quiet`: Quiet mode. Suppresses standard output, useful when you only want to save results to a file.
- `-o` or `--output`: Specify output filename. Default is `scan_results.csv`.
- `-w` or `--workers`: Specify the number of concurrent workers. Default is 50.

