from scapy.all import sniff, IP, TCP, UDP

def analyze(packet):
    print("\n--- Packet Captured ---")

    if IP in packet:
        print("Source:", packet[IP].src)
        print("Destination:", packet[IP].dst)
        print("Protocol:", packet[IP].proto)

        if TCP in packet:
            print("Layer: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:
            print("Layer: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        if packet.haslayer("Raw"):
            print("Payload:", packet["Raw"].load)
        else:
            print("Payload: None")

    else:
        print("Non-IP packet detected.")

sniff(prn=analyze, store=False