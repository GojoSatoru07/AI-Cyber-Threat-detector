from scapy.all import sniff
import csv
import time

def capture_packets(output_file="packets.csv"):
    def process_packet(packet):
        if packet.haslayer('IP'):
            packet_data = {
                "timestamp": time.time(),
                "src_ip": packet['IP'].src,
                "dst_ip": packet['IP'].dst,
                "protocol": packet['IP'].proto,
                "packet_length": len(packet)
            }
            with open(output_file, mode='a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=packet_data.keys())
                writer.writerow(packet_data)
            print(f"Captured packet: {packet_data}")
    sniff(prn=process_packet, store=0)

if __name__ == "__main__":
    capture_packets()
