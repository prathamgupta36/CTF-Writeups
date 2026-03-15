FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.1.2 bleach==6.3.0 requests==2.32.5

COPY app/ /app/
EXPOSE 5000

CMD ["python", "/app/app.py"]
