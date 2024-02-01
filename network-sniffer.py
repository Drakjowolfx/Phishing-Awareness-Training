from scapy.all import sniff

# Supported protocols
supported_protocols = ["arp", "icmp", "ipv4", "dns", "tcp", "udp", "http", "https"]

# Define a callback function to process each captured packet
def packet_callback(packet):
    print(packet.summary())  # Print a summary of the packet

# Prompt the user for the number of packets to sniff
num_packets = int(input("Enter the number of packets to sniff: "))

# Prompt the user for the protocol to filter for
protocol = input("Enter the protocol to filter for ARP, ICMP, IPv4, DNS, TCP, UDP, HTTP, HTTPS (no input = no filter): ").lower()

# Check if the protocol is supported
if protocol not in supported_protocols and protocol.strip() != "":
    print(f"Error: '{protocol}' is not a supported protocol.")
    exit()

# Initialize filter expression
filter_expr = ""

# Construct the filter expression based on the chosen protocol
if protocol == "arp":
    filter_expr = "arp"
elif protocol == "icmp":
    filter_expr = "icmp"
elif protocol == "ipv4":
    filter_expr = "ip"
elif protocol == "dns":
    filter_expr = "udp port 53"
elif protocol == "tcp":
    filter_expr = "tcp"
elif protocol == "udp":
    filter_expr = "udp"
elif protocol == "http":
    filter_expr = "tcp port 80"
elif protocol == "https":
    filter_expr = "tcp port 443"

# Start sniffing packets on the default network interface with the specified filter (if any)
if filter_expr:
    sniff(prn=packet_callback, count=num_packets, filter=filter_expr)
else:
    sniff(prn=packet_callback, count=num_packets)
