from fastapi import APIRouter, HTTPException

from app.core.network_scanner import NetworkFacade

from app.core.checks import ScanLan #Scan functions
from app.models.scan import NetworkScanModel