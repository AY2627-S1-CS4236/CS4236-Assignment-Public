FROM python:3.11-slim

WORKDIR /app

COPY server.py /app/server.py

EXPOSE 9003

CMD ["python", "-u", "server.py", "--host", "0.0.0.0", "--port", "9003"]
