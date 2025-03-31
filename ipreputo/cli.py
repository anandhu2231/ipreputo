import argparse
from ipreputo.ipreputo import process_ips

def main():
    parser = argparse.ArgumentParser(description="IP reputation checker")
    parser.add_argument("-i", "--input", required=True, help="Input file path (CSV/XLSX)")
    parser.add_argument("output", help="Output file path (CSV/XLSX)")
    
    args = parser.parse_args()
    process_ips(args.input, args.output)

if __name__ == "__main__":
    main()
