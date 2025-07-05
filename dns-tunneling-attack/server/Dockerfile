FROM python:latest

WORKDIR /app

EXPOSE 53/udp 3000/tcp

COPY main.py .
COPY objects/ ./objects

CMD ["python", "main.py"]