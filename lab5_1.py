from scapy.all import sniff, IP, TCP
from collections import defaultdict
import datetime
import logging

# Налаштування логів
logging.basicConfig(filename="logs.txt", level=logging.INFO, 
                    format="%(asctime)s - %(message)s")

# Словник для збереження даних про активність IP
traffic_data = defaultdict(list)

# Поріг для виявлення підозрілих дій
MAX_PACKETS = 100  # Максимальна кількість пакетів від одного IP за 5 секунд
SCAN_THRESHOLD = 10  # Кількість портів для сканування

# Функція аналізу пакетів
def analyze_packet(packet):
    if IP in packet:  # Перевіряємо, чи пакет має IP-заголовок
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Збереження активності
        now = datetime.datetime.now()
        traffic_data[src_ip].append(now)

        # Логування пакета
        logging.info(f"Packet: {src_ip} -> {dst_ip}, Protocol: {packet.proto}")

        # Виявлення сканування портів
        if TCP in packet:
            dst_port = packet[TCP].dport
            traffic_data[(src_ip, 'ports')].append(dst_port)
            unique_ports = set(traffic_data[(src_ip, 'ports')])
            if len(unique_ports) > SCAN_THRESHOLD:
                alert(f"Port scanning detected from {src_ip}! Ports: {unique_ports}")
                traffic_data[(src_ip, 'ports')].clear()

        # Виявлення великої активності
        recent_packets = [t for t in traffic_data[src_ip] if (now - t).seconds < 5]
        if len(recent_packets) > MAX_PACKETS:
            alert(f"High packet activity detected from {src_ip}: {len(recent_packets)} packets in 5 seconds.")
            traffic_data[src_ip] = [now]  # Очищення для подальшого аналізу

# Функція для сповіщення адміністратора
def alert(message):
    print(f"[ALERT] {message}")
    logging.info(f"[ALERT] {message}")

# Функція для перехоплення трафіку
def start_sniffing(interface):
    print(f"Starting packet capture on interface {interface}...")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    interface = input("Enter network interface to monitor (e.g., eth0, wlan0): ")
    start_sniffing(interface)
