from socket import gaierror

from scapy.data import TCP_SERVICES
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr


def syn_ack_scan(ip: str, ports: tuple) -> dict:
    """
    Выполняет SYN-сканирование по одному порту за раз.
    Возвращает словарь: {ip: {port: service}}.
    """
    result = {}  # Инициализация словаря результатов

    for port in ports:
        try:
            # Создаем SYN-пакет для одного порта
            request_syn = IP(dst=ip) / TCP(dport=port, flags="S")
            # Отправляем пакет и ждем ответа (1 повтор, таймаут 2 сек)
            answer = sr(request_syn, timeout=2, retry=1, verbose=False)[0]

            # Обработка ответа
            for sent, received in answer:
                if received.haslayer(TCP):
                    if received[TCP].flags == "SA":  # SYN/ACK (порт открыт)
                        ip_src = str(received[IP].src)
                        port_src = str(received[TCP].sport)
                        if ip_src not in result:
                            result[ip_src] = {}
                        result[ip_src][port_src] = TCP_SERVICES.get(received[TCP].sport, "Undefined")
                    elif received[TCP].flags == "RA":  # RST/ACK (порт закрыт)
                        print(f"Port {port} is closed")
                    else:
                        print(f"Port {port} received unexpected flags: {received[TCP].flags}")
                else:
                    print(f"Port {port} received unexpected response")
        except gaierror:
            raise ValueError(f"Не удалось разрешить адрес {ip}")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return result


# Пример использования
if __name__ == "__main__":
    try:
        result = syn_ack_scan("10.1.254.196", range(1, 1024))
        print(result)
    except ValueError as e:
        print(f"Error: {e}")
