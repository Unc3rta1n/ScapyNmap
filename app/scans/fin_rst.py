from socket import gaierror

from scapy.data import TCP_SERVICES
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from app.logger import logger


def fin_rst_scan(ip: str, ports: tuple[int]):
    """
    Выполняет FIN-сканирование по одному порту за раз.
    Возвращает словарь: {ip: {port: status_or_service}}.
    """
    result = {}  # Инициализация словаря результатов
    result[ip] = {}

    for port in ports:
        try:
            # Создаем FIN-пакет для одного порта
            request_fin = IP(dst=ip) / TCP(dport=port, flags="F")
            # Отправляем пакет и ждем ответа
            answer = sr1(request_fin, timeout=5, retry=2, verbose=False)
            if answer is None:  # Нет ответа
                logger.debug(f"Port {port} is open or filtered")
                result[ip][str(port)] = "open|filtered"
            elif answer.haslayer(TCP):
                if answer[TCP].flags == "RA":  # RST/ACK (порт закрыт)
                    logger.debug(f"Port {port} is closed")
                    # result[ip][str(port)] = "closed"
                else:
                    # Порт открыт (неожиданные флаги для FIN, но добавляем в результат)
                    try:
                        service = TCP_SERVICES[port]
                    except KeyError:
                        service = "Undefined"

                    logger.debug(
                        f"Port {port} received unexpected TCP flags: {answer[TCP].flags}, assuming open ({service})"
                    )
                    result[ip][str(port)] = f"open ({service})"
            else:
                logger.debug(f"Port {port} received unexpected response")
                result[ip][str(port)] = "unknown"
        except gaierror as ex:
            raise ValueError(f"Не удалось разрешить адрес {ip}") from ex
        except Exception as e:
            logger.error(f"Error scanning port {port}: {e}")
            if ip not in result:
                result[ip] = {}
            result[ip][str(port)] = "error"

    return result


result = fin_rst_scan(ip="10.94.204.254", ports=range(1, 1024))
logger.info(result)
