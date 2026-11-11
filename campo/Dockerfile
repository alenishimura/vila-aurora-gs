FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensor.py .
# roda sem root
RUN useradd -u 1001 -m sensor
USER sensor
CMD ["python", "-u", "sensor.py"]
