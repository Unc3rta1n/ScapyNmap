from socket import gaierror

from scapy.data import TCP_SERVICES
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from app.logger import logger


def syn_ack_scan(ip: str, ports: tuple[int]) -> dict:
    """
    Выполняет SYN-сканирование по одному порту за раз.
    Возвращает словарь: {ip: {port: service}}.
    """
    result = {}
    result[ip] = {}
    for port in ports:
        try:
            # Создаем SYN-пакет для одного порта
            request_syn = IP(dst=ip) / TCP(dport=port, flags="S")
            # Отправляем пакет и ждем ответа (увеличиваем таймаут и повторы)
            answer = sr1(request_syn, timeout=5, retry=2, verbose=False)

            # Обработка ответа
            if not answer:  # Нет ответа
                logger.debug(f"Port {port} is filtered or no response")
                continue


            if answer.haslayer(TCP):
                if answer[TCP].flags == "SA":  # SYN/ACK (порт открыт)
                    ip_src = str(answer[IP].src)
                    port_src = str(answer[TCP].sport)
                    sport = answer[TCP].sport
                    try:
                        result[ip_src][port_src] = TCP_SERVICES[sport]
                    except KeyError:
                        result[ip_src][port_src] = "Undefined"
                    logger.debug(f"Port {port} is open ({result[ip_src][port_src]})")
                elif answer[TCP].flags == "RA":  # RST/ACK (порт закрыт)
                    logger.debug(f"Port {port} is closed")
                else:
                    logger.debug(f"Port {port} received unexpected flags: {answer[TCP].flags}")
            else:
                logger.debug(f"Port {port} received unexpected response")
        except gaierror as ex:
            raise ValueError(f"Не удалось разрешить адрес {ip}") from ex
        except Exception as e:
            logger.error(f"Error scanning port {port}: {e}")

    return result


result = syn_ack_scan(ip="10.1.254.154", ports=range(5000, 5555))
logger.info(result)
