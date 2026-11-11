FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -u 1003 -m app
USER app
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]
