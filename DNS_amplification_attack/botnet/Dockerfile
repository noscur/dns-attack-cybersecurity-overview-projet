FROM python:3

WORKDIR /app

COPY botnet.py ./
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python3", "botnet.py"]