import subprocess
import nmap

def block_ip(ip_range):
    # Блокує вхідний трафік з певної IP-адреси або діапазону
    command = f'netsh advfirewall firewall add rule name="Block {ip_range}" dir=in action=block remoteip={ip_range}'
    subprocess.run(command, shell=True)

def allow_traffic_from_trusted(ip_range):
    # Дозволяє вхідний трафік лише з довірених джерел
    command = f'netsh advfirewall firewall add rule name="Allow {ip_range}" dir=in action=allow remoteip={ip_range}'
    subprocess.run(command, shell=True)

def restrict_port(port):
    # Обмежує доступ до певного порту
    command = f'netsh advfirewall firewall add rule name="Restrict Port {port}" dir=in action=block protocol=TCP localport={port}'
    subprocess.run(command, shell=True)

def scan_ports(ip_range, ports):
    # Сканує порти на заданій IP-адресі та визначає відкриті порти і сервіси
    active_hosts = []
    scanner = nmap.PortScanner()
    for ip in ip_range:
        print(f"Сканування хоста: {ip}")
        for port in ports:
            try:
                result = scanner.scan(ip, str(port))
                if result['scan'].get(ip, {}).get('tcp', {}).get(port, {}).get('state') == 'open':
                    active_hosts.append(ip)
                    print(f"Порт {port} відкритий на {ip}")
                    service = result['scan'][ip]['tcp'][port].get('name', 'Невідомий')
                    version = result['scan'][ip]['tcp'][port].get('version', 'Невідома версія')
                    print(f"Сервіс на порту {port}: {service}, Версія: {version}")
            except Exception as e:
                print(f"Помилка сканування: {e}")
    
    # Налаштування брандмауера для активних хостів
    for ip in active_hosts:
        allow_traffic_from_trusted(ip)
        print(f"Дозволено з'єднання з {ip} на основі результатів сканування")

# Приклад використання
scan_ports(['192.168.1.1', '18.244.146.21'], [22, 80, 443])
