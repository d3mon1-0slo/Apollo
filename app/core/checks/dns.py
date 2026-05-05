import socket
import asyncio

class DNSChecker:
    '''
        - takes input then kukunin lang natin / convert yung DNS to IP with socket pkg
    '''
    def _check_sync(self, hostname: str) -> dict:
        print(">>> resolving:", hostname)
        try:
            result = socket.getaddrinfo(hostname, None)
            ip     = result[0][4][0]
            print(">>> resolved:", ip)
            return {
                "dns_resolves": True,
                "ip"          : ip,
                "error"       : None,
            }
        except socket.gaierror as e:
            print(">>> failed:", e)
            return {
                "dns_resolves": False,
                "ip"          : None,
                "error"       : str(e),
            }
    async def check(self, hostname: str) -> dict:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._check_sync, hostname)