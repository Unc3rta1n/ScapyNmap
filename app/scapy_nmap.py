import time
from datetime import datetime, timedelta, timezone
from socket import gaierror

from scapy.data import TCP_SERVICES
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from app.logger import setup_logger
from app.scanner import Scanner


class ScapyNmap(Scanner):
    def __init__(self, args):
        super().__init__(args)
        self.logger = setup_logger("ScapyNmap", "DEBUG")

    def fin_scan(self):
        """
        Выполняет FIN-сканирование по одному порту за раз.
        Возвращает словарь: {ip: {port: status_or_service}}.
        """
        result = {}
        for ip in self.hostpool:
            for port in self.ports:
                try:
                    if ip not in result:
                        result[ip] = {}
                    request_fin = IP(dst=ip) / TCP(dport=port, flags="F")
                    response = sr1(request_fin, timeout=self.timeout, retry=self.retry, verbose=False, multi=False)

                    if response is None:
                        self.logger.debug(f"Port {port} is open or filtered")
                        result[ip][str(port)] = "open|filtered"

                    elif response.haslayer(TCP):
                        if response[TCP].flags == "RA":  # RST/ACK (порт закрыт)
                            self.logger.debug(f"Port {port} is closed")
                            # result[ip][str(port)] = "closed"
                        else:
                            # Порт открыт (неожиданные флаги для FIN, но добавляем в результат)
                            try:
                                service = TCP_SERVICES[port]
                            except KeyError:
                                service = "Undefined"

                            self.logger.debug(
                                f"Port {port} received unexpected TCP flags: {response[TCP].flags}, assuming open ({service})"
                            )
                            result[ip][str(port)] = f"open ({service})"
                    else:
                        self.logger.debug(f"Port {port} received unexpected response")
                        result[ip][str(port)] = "unknown"
                    time.sleep(self.delay)  # таймаут между пакетами
                except gaierror as ex:
                    raise ValueError(f"Address could not be resolved {ip}") from ex
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {e}")
                    if ip not in result:
                        result[ip] = {}
                    result[ip][str(port)] = "error"
        return result

    def syn_scan(self) -> dict:
        """
        Выполняет SYN-сканирование по одному порту за раз.
        Возвращает словарь: {ip: {port: service}}.
        """
        result = {}
        for ip in self.hostpool:
            for port in self.ports:
                try:
                    request_syn = IP(dst=ip) / TCP(dport=port, flags="S")
                    response = sr1(request_syn, timeout=self.timeout, retry=self.retry, verbose=False, multi=False)

                    if not response:
                        self.logger.debug(f"Port {port} is filtered or no response in {ip}")
                        continue

                    if response.haslayer(TCP):
                        if response[TCP].flags == "SA":  # SYN/ACK (порт открыт)
                            ip_src = str(response[IP].src)
                            port_src = str(response[TCP].sport)
                            sport = response[TCP].sport
                            if ip_src not in result:
                                result[ip_src] = {}
                            try:
                                result[ip_src][port_src] = TCP_SERVICES[sport]
                            except KeyError:
                                result[ip_src][port_src] = "Undefined"
                            self.logger.debug(f"Port {port} is open ({result[ip_src][port_src]})  in {ip}")
                        elif response[TCP].flags == "RA":  # RST/ACK (порт закрыт)
                            self.logger.debug(f"Port {port} is closed in {ip}")
                        else:
                            self.logger.debug(f"Port {port} received unexpected flags: {response[TCP].flags} in {ip}")
                    else:
                        self.logger.debug(f"Port {port} received unexpected response in {ip}")
                    time.sleep(self.delay)
                except gaierror as ex:
                    raise ValueError(f"Address could not be resolved {ip}") from ex
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {e}")

        return result

    def check_wing_server(self) -> None:
        self.vulnerable = {}

        for ip, services in self.result.items():
            if "21" in services.keys():
                banner = self._grab_ftp_banner(ip, 21)
                if banner and "Wing FTP" in banner:
                    self.vulnerable[ip] = True
                    continue
            if "80" in services.keys():
                resp = self._grab_http_header(ip, 80)
                if resp and "Wing FTP" in resp:
                    self.vulnerable[ip] = True
                    continue
            self.vulnerable[ip] = False

    def run(self):
        self.scan_start_time = int(datetime.now(tz=timezone.utc).timestamp())
        try:
            if self.syn:
                self.result = self.syn_scan()
            else:
                self.result = self.fin_scan()
            # print(self.result)
            if self.vuln:
                self.check_wing_server()
                print(self.vulnerable)
            self.scan_finish_time = int(datetime.now(tz=timezone.utc).timestamp())
        except Exception as ex:
            self.logger.error(f"{str(ex)}", exc_info=True)

    def pretty_print(self):
        print(self)
        delta_seconds = self.scan_finish_time - self.scan_start_time
        delta = timedelta(seconds=delta_seconds)
        print(f"Scan duration: {delta_seconds} seconds ({str(delta)})")
        for ip, services in self.result.items():
            print(f"IP {ip:^{30}}")
            print(f"{'PORT':<9} {'STATE':<8} {'SERVICE':<12}")

            for port, service in services.items():
                print(f"{port}/tcp{'':<3} {'open':<8} {service:<12}")
        if self.vuln:
            if any(self.vulnerable.get(ip, False) for ip in self.result):
                print("\nVulnerability Summary:")
                for ip in self.result:
                    if self.vulnerable.get(ip, False):
                        print(f"- {ip}: POSSIBLE: CVE-2025-47812: Wing FTP Server Remote Code Execution")
