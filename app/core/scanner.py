from datetime import datetime, timezone
from urllib.parse import urlparse

from app.core.checks.ssl import SSLChecker
from app.core.checks.headers import HeaderChecker
from app.core.checks.dns import DNSChecker
from app.core.checks.osint import OSINTChecker
from app.core.checks.check_ports import PORTScanner

from app.models.scan import ScanResponse
from app.models.scan import Scanrequest

class ScannerFacade:
    def __init__(self):
        self.ssl = SSLChecker()
        self.header = HeaderChecker()
        self.dns = DNSChecker()
        self.osint = OSINTChecker()
        self.port = PORTScanner()

    async def scan(self, url:str) -> dict:

        hostname = urlparse(str(url)).hostname
        osint_result = await self.osint.check(hostname, str(url))
        port_scanner = await self.port.scan(hostname)
        ssl_result = await self.ssl.check(hostname)
        header_result = await self.header.check(str(url))
        dns_result = await self.dns.check(hostname)


        return ScanResponse(
            url = url,
            ssl = ssl_result,
            dns = dns_result,
            headers = header_result,
            osint = osint_result,
            port_scans = port_scanner, 
            risk_level = self._calculate_risk(ssl_result,dns_result,header_result, osint_result),
            scanned_at = datetime.now(timezone.utc)
        )
    
    def _calculate_risk(self, ssl:dict, dns:dict, headers:dict, osint:dict) -> str:

        if not ssl["ssl_valid"] or not dns["dns_resolves"]:
            return "High"
        
        if osint["whois"]["risk_flag"] or osint["reputation"]["risk_flag"]:
            return "High"

        
        missing = headers.get("missing", [])
        if len(missing) >= 2 or osint["server"]["risk_flag"]:
            return "Medium"
        
        return "Low"



