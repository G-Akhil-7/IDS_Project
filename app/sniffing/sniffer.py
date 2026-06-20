from scapy.all import sniff
from app.detection.detector import detect

def process_packet(packet):

    print(packet.summary())

    detect(packet)

def start_sniffing():

    sniff(iface="lo", prn=process_packet, store=False)
