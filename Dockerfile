FROM python:3.11

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y whois

RUN pip install --no-cache-dir -r requirements.txt

CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:$PORT"]