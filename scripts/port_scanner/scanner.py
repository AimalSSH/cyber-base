import argparse
from scapy.all import *
import socket
import json
import re
import time

conf.verb = 0

def create_parser():
    parser = argparse.ArgumentParser(
        description='Сканер портов - инструмент для анализа сетевых портов'
    )
    
    parser.add_argument(
        '--host',
        type=str,
        required=True,
        help='Целевой хост (IP адрес или доменное имя)'
    )

    port_group = parser.add_mutually_exclusive_group(required=True)
    
    port_group.add_argument(
        '--port',
        type=int,
        help='Сканировать конкретный порт (число от 1 до 65535)'
    )

    port_group.add_argument(
        '--ports',
        type=str,
        help='Диапазон портов для сканирования (формат: 20-100) или список портов (80,443,22)'
    )

    parser.add_argument(
        '--check',
        action='store_true',
        help='Проверить доступность хоста (ping) перед сканированием'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Экспорт результатов в JSON формате'
    )

    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Таймаут соединения в секундах (по умолчанию: 1.0)'
    )

    return parser

def parse_ports(ports_str):
    """Парсит строку портов в список чисел"""
    ports = []
    
    if '-' in ports_str:
        try:
            start, end = map(int, ports_str.split('-'))
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                ports = list(range(start, end + 1))
            else:
                raise ValueError("Диапазон портов должен быть от 1 до 65535")
        except ValueError:
            raise ValueError("Неверный формат диапазона портов. Используйте: start-end")
    
    elif ',' in ports_str:
        try:
            ports = [int(port.strip()) for port in ports_str.split(',')]
            if not all(1 <= port <= 65535 for port in ports):
                raise ValueError("Все порты должны быть в диапазоне от 1 до 65535")
        except ValueError:
            raise ValueError("Неверный формат списка портов. Используйте: port1,port2,port3")
    
    else:
        try:
            port = int(ports_str)
            if 1 <= port <= 65535:
                ports = [port]
            else:
                raise ValueError("Порт должен быть в диапазоне от 1 до 65535")
        except ValueError:
            raise ValueError("Неверный формат порта")
    
    return ports

def scan_port(target_ip, port, timeout_val):
    """Сканирует один порт и возвращает результат"""
    result = {
        'port': port,
        'status': 'unknown'
    }
    
    try:
        syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        response = sr1(syn_packet, timeout=timeout_val, verbose=0)

        if response is None:
            result['status'] = 'filtered'
            if not args.json:
                print(f"[-] Порт {port}: фильтруется или не отвечает")
        
        elif response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            
            if tcp_layer.flags == 0x12:
                result['status'] = 'open'

                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=0)
                if not args.json:
                    print(f"[+] Порт {port}: открыт")
            
            elif tcp_layer.flags == 0x14: 
                result['status'] = 'closed'
                if not args.json:
                    print(f"[-] Порт {port}: закрыт")
            
            else:
                result['status'] = 'unexpected_flags'
                if not args.json:
                    print(f"[-] Порт {port}: неожиданные флаги: {tcp_layer.flags:#04x}")
        
        else:
            result['status'] = 'icmp_error'
            if not args.json:
                print(f"[-] Порт {port}: получен ICMP ответ")
    
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        if not args.json:
            print(f"[-] Порт {port}: ошибка сканирования - {e}")
    
    return result

def resolve_host(hostname):
    """Разрешает доменное имя в IP адрес"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        raise ValueError(f"Не удается разрешить hostname: {hostname}")

def check_host_up(target_ip):
    """Проверяет доступность хоста"""
    try:
        ping_pkt = IP(dst=target_ip)/ICMP()
        response = sr1(ping_pkt, timeout=2, verbose=0)
        
        return response is not None
    except Exception as e:
        if not args.json:
            print(f"[-] Ошибка ping: {e}")
        return False

def main():
    global args
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        target_ip = resolve_host(args.host)
        if not args.json:
            print(f"[+] Целевой IP: {target_ip}")
    except ValueError as e:
        print(f"Ошибка: {e}")
        return
    
    if args.check:
        host_up = check_host_up(target_ip)
        if not args.json:
            if host_up:
                print(f"[+] Хост {target_ip} доступен")
            else:
                print(f"[-] Хост {target_ip} недоступен")
        
        if not host_up:
            if not args.json:
                print("Прерывание сканирования: хост недоступен")
            return
    
    ports_to_scan = []
    if args.port:
        ports_to_scan = [args.port]
    elif args.ports:
        try:
            ports_to_scan = parse_ports(args.ports)
        except ValueError as e:
            print(f"Ошибка: {e}")
            return
    
    if not args.json:
        message(args.host, ports_to_scan)
    
    results = []
    for port in ports_to_scan:
        result = scan_port(target_ip, port, args.timeout)
        results.append(result)

        time.sleep(0.1)
    
    if args.json:
        output = {
            'target': args.host,
            'target_ip': target_ip,
            'ports_scanned': len(ports_to_scan),
            'results': results
        }
        print(json.dumps(output, indent=2))

def message(host, ports):
    """Выводит информационное сообщение"""
    print("========PACKEGE EXPLOIT========")
    print(f"RHOST: {host}")
    if len(ports) == 1:
        print(f"RPORT: {ports[0]}")
    else:
        print(f"RPORTS: {ports}")
    print("=" * 30)

if __name__ == "__main__":
    main()