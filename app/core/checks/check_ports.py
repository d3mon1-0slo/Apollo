import socket

PORT_LABELS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


class PORTScanner:

    def __init__(self, timeout: float = 0.5):
        self.timeout = timeout
        self.target_ip = None
        self.results = []

    def resolve(self, hostname:str) -> bool:
        '''
            - Convert domain into IP 
        '''
        try:
            self.target_ip = socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False
        
    async def scan_port(self, port : list[int]) -> list[dict]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            return s.connect_ex((self.target_ip, port)) == 0
        
    async def scan(self, hostname : str, ports : list[int] = [21, 22, 23, 25, 53, 80, 110, 443]) -> list[dict]:
        if not self.resolve(hostname):
            return []
        
        self.results = []
        for port in ports:
            is_open = await self.scan_port(port)

            if is_open:
                entry = {
                    "port":  port,
                    "label": PORT_LABELS.get(port, "Unknown"),
                    "open":  is_open,
                }
                self.results.append(entry)
        return self.results
    

