import ipaddress

from app.config import TimeoutEnum


class Scanner:
    def __init__(self, args):
        self.ports = self._parse_ports(args.p)
        self.hostpool = self._validate_hostpool(args.h)
        self.syn = args.syn
        self.fin = args.fin
        self.timing = TimeoutEnum[f"T{args.T}"] if args.T is not None else TimeoutEnum.T3
        self.delay, self.timeout, self.retry = self.timing.value

    def _parse_ports(self, ports: str) -> list[int]:
        """Парсинг портов из строки в список

        Args:
            ports (str): строка вида "1-1000" "1,1000"

        Raises:
            ValueError: При ошибке парсинга

        Returns:
            list[int]: список портов, которые будут сканироваться
        """
        try:
            if "-" in ports:
                start, end = map(int, ports.split("-"))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    raise ValueError("Ports must be between 1 and 65535, and start <= end")
                return list(range(start, end + 1))
            return [int(port) for port in ports.split(",") if 1 <= int(port) <= 65535]
        except ValueError as e:
            raise ValueError(f"Invalid port format: {ports}. Use '1-1000' or '80,443,8080'") from e

    def _validate_host(self, host: str) -> bool:
        """Валидация айпи адреса

        Args:
            host (str): строка вида "192.168.1.0"

        Returns:
            bool: Флаг, корректный ли айпи адрес передан
        """
        if not host:
            return False
        try:
            ipaddress.IPv4Address(host)
            return True
        except ipaddress.AddressValueError:
            return False

    def _validate_hostpool(self, hostpool: str) -> list[str]:
        """Парсинг и валидация пула айпи адресов

        Args:
            hostpool (str): строка вида "192.168.1.0-192.168.2.0" "192.168.1.0/24

        Raises:
            ValueError: При ошибке парсинга

        Returns:
            list[str]: Список айпи адресов, которые будут сканироваться
        """
        if not hostpool:
            raise ValueError("Use --h flag to set host addresses to scan")
        try:
            if "-" in hostpool:
                start_ip, end_ip = hostpool.split("-")
                start_ip = start_ip.strip()
                end_ip = end_ip.strip()
                start = int(ipaddress.IPv4Address(start_ip))
                end = int(ipaddress.IPv4Address(end_ip))
                if start > end:
                    raise ValueError(f"Start IP {start_ip} must be less than or equal to end IP {end_ip}")
                return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
            elif "/" in hostpool:
                network = ipaddress.IPv4Network(hostpool, strict=False)
                return [str(ip) for ip in network]
            else:
                ip_list = hostpool.split(",")
                valid_ips = []
                for ip in ip_list:
                    ip = ip.strip()
                    ipaddress.IPv4Address(ip)
                    valid_ips.append(ip)
                return valid_ips
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IPv4 address or format in pool: {hostpool}") from e
        except ipaddress.NetmaskValueError as e:
            raise ValueError(f"Invalid CIDR notation: {hostpool}") from e

    def run(self):
        raise NotImplementedError("The method is not implemented in the base class")

    def __str__(self) -> str:
        return (
            f"Scanner(ports={self.ports}, host={self.hostpool}, "
            f"hostpool={self.hostpool}, syn_scan={self.syn}, timing={self.timing})"
        )
