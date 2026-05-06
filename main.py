from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import scans
from app.api import  network_endpoint


from app.config.settings import settings


# Create metadata for /docs

app = FastAPI( 
    title=settings.APP_NAME,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/scans", tags=["scan"])
# app.include_router(network_endpoint.router, prefix="/network", tags=["network"])


@app.on_event("startup")
async def startup():
    pass


@app.on_event("shutdown")
async def shutdown():
    pass