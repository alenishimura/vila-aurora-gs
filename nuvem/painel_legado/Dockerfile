FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.0 psycopg2-binary==2.9.10
COPY app.py .
CMD ["python", "-u", "app.py"]
