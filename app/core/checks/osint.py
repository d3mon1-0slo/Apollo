import httpx 
import whois
from datetime import datetime, timezone
from ipwhois import IPWhois
import socket

class OSINTChecker:
    async def check(self, hostname : str, url : str) -> dict:
        print(hostname)
        whois_data = await self._whois_lookup(hostname)
        if not whois_data['whois']: # Backup if mag fail si whoislookup
            whois_data = await self._IPwhois_lookup(hostname)
        reputataion = await self._ip_reputation(hostname)
        server_info = await self._server_fingerprint(url)
        
        return {
            "whois" : whois_data,
            "reputation" : reputataion,
            "server_info" : server_info
        }
    
    async def _whois_lookup(self, hostname:str) -> dict:
        try:
            w = whois.whois(hostname)

            # age calculation
            creation_date = w.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now(timezone.utc) - creation_date).days if creation_date else None
            result_data ={
                'whois' : True,
                "registrar"    : w.registrar,
                "creation_date": str(creation_date),
                "expiry_date"  : str(w.expiration_date),
                "age_days"     : age_days,
                "country"      : w.country,
                # if domain is pretty new can be a target for phising attack 🚩
                "risk_flag"    : age_days is not None and age_days < 30
            }
            return result_data
        
        except Exception:
             return {
                "whois" : False,
                "registrar"    : None,
                "creation_date": None,
                "expiry_date"  : None,
                "age_days"     : None,
                "country"      : None,
                "risk_flag"    : False
            }
        

    
    async def _IPwhois_lookup(self, hostname: str) -> dict:
        try:
            ip = socket.gethostbyname(hostname)

            obj = IPWhois(ip)
            res = obj.lookup_rdap()

            network = res.get("network", {})
            events = network.get("events", [])

            # find registration date
            reg_date = None
            for event in events:
                if event.get("event_action") == "registration":
                    reg_date = event.get("event_date")
                    break

            if reg_date:
                reg_date = datetime.fromisoformat(reg_date.replace("Z", "+00:00"))

            age_days = (
                (datetime.now(timezone.utc) - reg_date).days
                if reg_date else None
            )

            return {
                "ip": ip,
                "asn": res.get("asn"),
                "org": res.get("network", {}).get("name"),
                "country": res.get("network", {}).get("country"),
                "creation_date": str(reg_date),  # IP registration, not domain
                "age_days": age_days,
                "risk_flag": age_days is not None and age_days < 30
            }

        except Exception as e:
            return {
                "ip": None,
                "asn": None,
                "org": None,
                "country": None,
                "creation_date": None,
                "age_days": None,
                "risk_flag": False
            }
    
    async def _ip_reputation(self, hostname : str) -> dict:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://ip-api.com/json/{hostname}",
                    timeout=5
                )
                data = response.json()
                return {
                    "ip"          : data.get("query"),
                    "country"     : data.get("country"),
                    "isp"         : data.get("isp"),
                    "org"         : data.get("org"),
                    "is_proxy"    : data.get("proxy", False),
                    "risk_flag"   : data.get("proxy", False)
                }
        except Exception:
            return {
                "ip"       : None,
                "country"  : None,
                "isp"      : None,
                "org"      : None,
                "is_proxy" : False,
                "risk_flag": False
            }
        
    async def _server_fingerprint(self, url: str) -> dict:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=5, follow_redirects=True)
                headers  = response.headers

                server      = headers.get("server")
                powered_by  = headers.get("x-powered-by")

                return {
                    "server"    : server,
                    "powered_by": powered_by,
                    "risk_flag" : server is not None or powered_by is not None,
                    "risk_reason": "Server info exposed — attackers can fingerprint your stack" if (server or powered_by) else None
                }

        except Exception:
            return {
                "server"     : None,
                "powered_by" : None,
                "risk_flag"  : False,
                "risk_reason": None
            }