# Cyber-Base

Коллекция инструментов для кибербезопасности и образовательных материалов.

## Отказ от ответственности
Инструменты предназначены **только для образовательных целей** и тестирования систем с разрешения владельца. Использование без согласия нарушает законы о компьютерной безопасности.

## Структура

```
cyber-base/
├── scripts/          # Практические инструменты
│   ├── ftp_exploit/      # FTP клиент
│   ├── fuzzers/          # API и Web фаззеры
│   ├── packet_scripts/   # TCP анализ
│   ├── port_scanner/     # Сканер портов
│   └── processes_linux/  # Исследование процессов
├── nodes/            # Теоретические заметки
└── captures/         # pcap файлы
```

## Инструменты

### [Port Scanner](scripts/port_scanner/README.md)
TCP SYN сканер портов
```bash
cd scripts/port_scanner
sudo python3 port_scanner.py --host 192.168.1.1 --ports 20-100
```

### [FTP Client](scripts/ftp_exploit/README.md)
FTP клиент для листинга файлов
```bash
cd scripts/ftp_exploit
python ftp_client.py -s test.rebex.net -u demo -w password
```

### [API Fuzzer](scripts/fuzzers/README%20API%20Fuzzer.md)
Мутационный фаззер для REST API
```bash
cd scripts/fuzzers
python api_fuzzer.py -t http://localhost:3000/api -s seed.json
```

### [Web Parameter Fuzzer](scripts/fuzzers/README%20Web%20Parameter%20Fuzzer.md)
Фаззинг веб-параметров и форм
```bash
cd scripts/fuzzers
python web_fuzzer.py -u "https://example.com/page.php?id=1"
```

### [TCP Window Tests](scripts/packet_scripts/README.md)
Тестирование TCP опций и анализ pcap
```bash
cd scripts/packet_scripts
python listening_server_ack.py  # сервер
python tcp_real_client_clean.py # клиент
python pcap_parselite.py        # анализ
```

### [Process Tools (Linux)](scripts/processes_linux/README.md)
Исследование межпроцессного взаимодействия
```bash
cd scripts/processes_linux
python3 buffer_victim.py          # жертва
python3 inspect_maps.py <PID>     # просмотр памяти
python3 buffer_attacker.py <PID> <ADDR> <SIZE> # чтение
```

## Теория

- [TCP Window Size и Window Scale](nodes/TCP%20Window%20Size%20и%20Window%20Scale.md)
- [TCP Options (MSS, WScale, Timestamps)](nodes/TCP%20Options.md)
- [RTO и Retransmission](nodes/RTO%20и%20Retransmission.md)
- [ТОП-7 логов Linux](nodes/ТОП-7%20логов%20Linux.md)

## Захваты трафика

- `captures/real_stack.pcap` - реальный TCP трафик
- `captures/window_options.pcap` - SYN-пакеты с TCP опциями

Анализ в Wireshark:
```bash
wireshark captures/window_options.pcap
```

## Установка

```bash
git clone https://github.com/AimalSSH/cyber-base.git
cd cyber-base
```

### Зависимости
```bash
pip install scapy requests beautifulsoup4 pyshark pandas psutil
```

### Настройка Linux (для process tools)
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

## Требования

- Python 3.6+
- Права root для порт-сканера и packet_scripts
- Linux для process tools

## Лицензия
Учебный проект. Свободное использование в образовательных целях.
