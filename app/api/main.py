from fastapi import FastAPI

app = FastAPI(
    title="DFIR Investigation API",
    description="Backend API for Windows and Linux DFIR investigations",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "dfir-api",
        "version": "0.1.0",
    }
