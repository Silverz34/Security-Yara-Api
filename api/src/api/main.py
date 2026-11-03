from fastapi import FastAPI

app = FastAPI(title="SecureYara API")


@app.get("/health")
def health():
    return {"status": "ok"}
