FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc build-essential curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=15s --start-period=180s --retries=3 \
  CMD curl -f http://localhost:8000/ready || exit 1

CMD ["bash", "-c", "python -m scheduler.scheduler & uvicorn api.main:app --host 0.0.0.0 --port 8000 & streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0"]
