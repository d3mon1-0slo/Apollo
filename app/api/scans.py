from fastapi import APIRouter,HTTPException

from app.models.scan import Scanrequest, ScanResponse
from app.core.scanner import ScannerFacade

router = APIRouter()
scanner = ScannerFacade()


@router.post('/', response_model=ScanResponse)
async def scan_url(request: Scanrequest):
    '''
        - validate incoming data via Scanrequest
        - pass it to the scanner object
        - validate the response automatically on response_model parameter
    '''
    try:
        return await scanner.scan(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/results')
async def results():
    pass

@router.get("result/{scan_id}")
async def result(scan_id: int):
    pass