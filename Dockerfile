FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 3128

ENTRYPOINT ["mitmdump"]
CMD ["--listen-host", "0.0.0.0", "--listen-port", "3128", "--set", "block_global=false", "-s", "/app/main.py"]