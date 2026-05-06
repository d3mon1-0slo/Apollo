from pydantic import BaseModel, HttpUrl
from datetime import datetime



# validate incoming data from "scans" endpoint 
# para walang manual validation

class Scanrequest(BaseModel):
    url : HttpUrl

class ScanResponse(BaseModel):
    url: HttpUrl
    ssl: dict
    dns: dict
    headers: dict
    risk_level: str 
    osint : dict
    port_scans : list
    scanned_at: datetime
