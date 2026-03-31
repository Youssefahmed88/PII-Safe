import logging
from fastapi import FastAPI
from app.api.v1.router import router as v1_router

# Setting up production logs for audit-trail tracking
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PII-Safe-Audit")

app = FastAPI(
    title="PII-Safe Production Middleware",
    description="Defense-in-depth sanitization for Agentic AI workflows.",
    version="1.0.0"
)

# Register the API routes
app.include_router(v1_router)

@app.get("/health")
async def health_check():
    """
    Basic heartbeat endpoint to ensure the service is alive.
    """
    return {"status": "healthy", "version": "1.0.0"}

if __name__ == "__main__":
    import uvicorn
    # Start the server locally for testing
    uvicorn.run(app, host="127.0.0.1", port=8000)
