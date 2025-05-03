import csv
import random
import time
import os

def generate_packets(output_file="packets.csv", num_packets=1000):
    protocols = [1, 6, 17]  # ICMP, TCP, UDP
    output_path = os.path.join(os.getcwd(), output_file)

    with open(output_path, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "dst_ip", "protocol", "packet_length"])
        writer.writeheader()

        for _ in range(num_packets):
            packet = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "src_ip": f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "dst_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "protocol": random.choice(protocols),
                "packet_length": random.randint(20, 1500)
            }
            writer.writerow(packet)

    print(f"[OK] Generated {num_packets} packets at: {output_path}")

if __name__ == "__main__":
    print("[DEBUG] Starting generate_packets")
    generate_packets()
    print("[DEBUG] Finished generate_packets")
