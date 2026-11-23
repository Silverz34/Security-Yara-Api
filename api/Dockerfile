FROM python:3.14-slim AS build
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.14-slim
RUN useradd --create-home --uid 10001 appuser \
 && mkdir /data && chown appuser /data
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY src ./src
COPY rules ./rules
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH=/app/src
USER appuser
EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
