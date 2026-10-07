from python:3.12-slim

workdir /srv/app

copy requirements.txt .
run pip install --no-cache-dir -r requirements.txt

copy . .

expose 8000
user 10001

cmd ["gunicorn", "--bind", "0.0.0.0:8000", "app:create_app()"]
