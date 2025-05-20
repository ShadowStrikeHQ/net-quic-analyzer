import socket
import argparse
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Captures and analyzes QUIC protocol handshakes and streams.")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface to capture QUIC traffic on (default: eth0)")
    parser.add_argument("--port", type=int, default=4433, help="QUIC port to monitor (default: 4433)")
    parser.add_argument("--output", type=str, help="File to save captured QUIC data (optional)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--filter", type=str, help="BPF filter for capturing specific QUIC traffic (optional)")
    return parser

def capture_quic_traffic(interface, port, output_file, bpf_filter=None):
    """
    Captures QUIC traffic on the specified interface and port.

    Args:
        interface (str): The network interface to capture traffic on.
        port (int): The QUIC port to monitor.
        output_file (str): The file to save captured data to (optional).
        bpf_filter (str): BPF filter for capturing specific QUIC traffic (optional).
    """
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) # 3 for all protocol
        sock.bind((interface, 0))

        # Apply BPF filter if provided
        if bpf_filter:
            try:
                 import bpf # Import bpf module only if filter specified. Prevent dependency issues.
                 sock.setsockopt(socket.SOL_SOCKET, socket.SO_ATTACH_FILTER, bpf.compile_string(bpf_filter))

            except ImportError as e:
                 logging.error(f"BPF library not found. Please install it. {e}")
                 sys.exit(1)

            except Exception as e:
                 logging.error(f"Failed to apply BPF filter: {e}")
                 sys.exit(1)

        logging.info(f"Capturing QUIC traffic on interface {interface}, port {port}")
        if bpf_filter:
            logging.info(f"Using BPF Filter: {bpf_filter}")


        with open(output_file, 'wb') as outfile if output_file else sys.stdout as outfile:  # Use stdout if no file provided
            while True:
                packet, addr = sock.recvfrom(65535)  # Receive up to 65535 bytes

                # Basic check for QUIC - look for QUIC common header (e.g., Version Negotiation packet)
                if len(packet) > 0 and (packet[0] & 0x80 == 0 or packet[0] & 0x40 == 0): # Simplified initial QUIC detection. Needs further refinement
                    logging.debug("Potential QUIC packet received.")
                    try:
                        # Basic packet processing/analysis (can be expanded)
                        # For now, just log the packet data.
                        # In a real implementation, you would decode QUIC headers, etc.

                        if output_file:
                            outfile.write(packet)
                        else:  # Writing to stdout
                            try:
                                # Attempt to decode as UTF-8, if not, fallback to repr
                                outfile.write(packet.hex() + '\n')
                            except UnicodeDecodeError:
                                outfile.write(repr(packet) + '\n')

                    except Exception as e:
                        logging.error(f"Error processing packet: {e}")


    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except KeyboardInterrupt:
        logging.info("Capture stopped.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if 'sock' in locals(): # Check to prevent error if socket wasn't properly initialized.
            sock.close() # Close socket if it's open.
            logging.info("Socket closed.")


def main():
    """
    Main function to parse arguments and start QUIC traffic capture.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Set logging level to DEBUG if verbose

    # Input validation
    if args.port < 1 or args.port > 65535:
        logging.error("Invalid port number. Port must be between 1 and 65535.")
        sys.exit(1)

    try:
        capture_quic_traffic(args.interface, args.port, args.output, args.filter)
    except Exception as e:
        logging.error(f"An error occurred: {e}")


if __name__ == "__main__":
    """
    Entry point of the script.
    """
    main()

# Usage examples:
# 1. Capture QUIC traffic on eth0, port 4433, and save to quic_capture.pcap:
#    python main.py --interface eth0 --port 4433 --output quic_capture.pcap
#
# 2. Capture QUIC traffic on eth0, port 4433, and print to standard output:
#    python main.py --interface eth0 --port 4433
#
# 3. Capture QUIC traffic with a specific BPF filter:
#    python main.py --interface eth0 --port 4433 --filter "udp port 4433"
#
# 4. Enable verbose logging:
#    python main.py --interface eth0 --port 4433 --verbose