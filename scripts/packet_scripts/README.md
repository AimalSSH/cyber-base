# TCP Window Tests - README
## Описание проекта
Набор Python-скриптов для тестирования TCP-соединений, анализа оконных опций и обработки сетевых захватов.
## Файлы
`tcp_window_test.py`
Генерирует SYN-пакеты с различными опциями TCP (MSS, WScale) для анализа поведения оконного масштабирования. Сохраняет пакеты в `window_options.pcap`.

`tcp_real_client.py`
Реализует TCP-клиент с задержкой подтверждений (delayed ACK) для тестирования стека TCP. Отправляет 3 сообщения с паузой 0.35 секунды.

`tcp_real_client_clean.py`
Простой TCP-клиент с использованием стандартного сокета. Отправляет 3 сообщения и получает ответ.

`listening_server_ack.py`
TCP-сервер, слушающий порт 40001. Отвечает на сообщения префиксом "ACK:" и первыми 10 байтами.

`pcap_parselite.py`
- Анализирует pcap-файлы с TCP-пакетами. Извлекает:
- Временные метки
- IP-адреса и порты
- Флаги TCP
- Размер окна
- Опции (MSS, WScale, timestamp)
- Сохраняет результаты в CSV

`pcap_find_retrans.py`
Обнаруживает повторные передачи TCP на основе последовательных номеров. Вычисляет RTT для подтверждённых пакетов.

`advanced_tcp_analysis.csv`
Пример выходных данных анализа — таблица с информацией о пакетах из real_stack.pcap.

## Пример использования

# Запуск сервера
```bash
python listening_server_ack.py
```

# В другом терминале - клиент
```bash
python tcp_real_client_clean.py
```

# Генерация SYN-пакетов
```bash
python tcp_window_test.py
```

# Анализ pcap
```bash
python pcap_parselite.py
```

## Зависимости
- Python 3.6+
- scapy
- pyshark
- pandas
- tshark (утилита Wireshark)

## Установка:
```bash
pip install scapy pyshark pandas
```