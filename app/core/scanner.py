from datetime import datetime, timezone
from urllib.parse import urlparse

from app.core.checks.ssl import SSLChecker
from app.core.checks.headers import HeaderChecker
from app.core.checks.dns import DNSChecker

from app.models.scan import ScanResponse
from app.models.scan import Scanrequest

class ScannerFacade:
    def __init__(self):
        self.ssl = SSLChecker()
        self.header = HeaderChecker()
        self.dns = DNSChecker()

    async def scan(self, url:str) -> dict:

        hostname = urlparse(str(url)).hostname
        print(f"hostname: {hostname}")

        ssl_result = await self.ssl.check(hostname)
        header_result = await self.header.check(str(url))
        dns_result = await self.dns.check(hostname)


        return ScanResponse(
            url = url,
            ssl = ssl_result,
            dns = dns_result,
            headers = header_result,
            risk_level = self._calculate_risk(ssl_result,dns_result,header_result),
            scanned_at = datetime.now(timezone.utc)
        )
    
    def _calculate_risk(self, ssl:dict, dns:dict, headers:dict) -> str:

        if not ssl["ssl_valid"] or not dns["dns_resolves"]:
            return "High"
        
        missing = headers.get("missing", [])
        if len(missing) >= 2:
            return "Medium"
        
        return "Low"



