from scapy.all import wrpcap, Ether, IP, TCP, UDP, ARP, DNS, DNSQR
import time

def generate_test_pcap(filename="test_traffic.pcap"):
    packets = []
    
    # 1. Normal Traffic
    for i in range(50):
        p = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=12345+i, dport=80, flags="PA")
        packets.append(p)
    
    # 2. Port Scan Attack
    for port in range(20, 100):
        p = Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5555, dport=port, flags="S")
        packets.append(p)
        
    # 3. SYN Flood
    for i in range(100):
        p = Ether() / IP(src="192.168.1.66", dst="192.168.1.1") / TCP(sport=1000+i, dport=443, flags="S")
        packets.append(p)

    # 4. DNS Tunneling
    for i in range(20):
        long_name = "data-chunk-" + "a" * 60 + ".malicious.com"
        p = Ether() / IP(src="192.168.1.75", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname=long_name))
        packets.append(p)

    # 5. ARP Spoofing
    p1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
    p2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    packets.append(p1)
    packets.append(p2)

    wrpcap(filename, packets)
    print(f"Generated {len(packets)} packets in {filename}")

if __name__ == "__main__":
    generate_test_pcap()
