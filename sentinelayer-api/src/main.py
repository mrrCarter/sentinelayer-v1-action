from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .middleware.request_id import RequestIDMiddleware
from .middleware.error_handler import http_exception_handler
from .routes import health, telemetry, runs, artifacts, stats, auth, deletion
from .db.connection import init_db, close_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(
    title="Sentinelayer API",
    version="1.0.0",
    docs_url="/docs",
    lifespan=lifespan,
)

# Exception handlers
app.add_exception_handler(HTTPException, http_exception_handler)

# Middleware (order matters - first added = outermost)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://sentinelayer.com", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(health.router, tags=["Health"])
app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
app.include_router(telemetry.router, prefix="/api/v1", tags=["Telemetry"])
app.include_router(runs.router, prefix="/api/v1", tags=["Runs"])
app.include_router(artifacts.router, prefix="/api/v1", tags=["Artifacts"])
app.include_router(stats.router, prefix="/api/v1", tags=["Stats"])
app.include_router(deletion.router, prefix="/api/v1", tags=["Deletion"])
