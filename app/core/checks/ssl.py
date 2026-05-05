import ssl
import socket
import asyncio
from datetime import datetime, timezone

class SSLChecker:
    '''
        - takes input hostname as target natin
        - create SSL secure config
        - create TCP connection
        - wrap it up with SSL
        - get SSL cert and verify the expiration date 
    '''

    def _check_sync(self,hostname:str) -> dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (expiry_date - datetime.now(timezone.utc)).days
                    return {
                        "ssl_valid"      : True,
                        "expires_in_days": days_left,
                        "expired"        : days_left <= 0,
                        "error"          : None,
                    }
        except ssl.SSLCertVerificationError as e:
            return {"ssl_valid": False, "expires_in_days": 0, "expired": True, "error": str(e)}
        except Exception as e:
            return {"ssl_valid": False, "expires_in_days": 0, "expired": True, "error": str(e)}

    async def check(self, hostname: str) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._check_sync, hostname)