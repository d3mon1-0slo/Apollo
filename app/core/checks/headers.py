import httpx


class HeaderChecker:

    '''
        - takes target url
        - follow if redirect
        - check if header contains the pre-defined headers
        - return None if not available
    '''

    SECURITY_HEADERS = [
        "strict-transport-security",  
        "content-security-policy",    
        "x-frame-options",           
        "x-content-type-options",   
    ]

    async def check(self, url: str) -> dict:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=5, follow_redirects=True)
                headers  = response.headers

                results = {}
                for header in self.SECURITY_HEADERS:
                    results[header] = headers.get(header) is not None

                results["missing"] = [h for h, present in results.items() if not present]

                return results

        except Exception:
            return {header: False for header in self.SECURITY_HEADERS}