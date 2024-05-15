FROM python:3.9

RUN apt-get update && \
    apt-get install -y nano

WORKDIR /challenge_meli

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 3000

ENV MYSQL_HOST=localhost
ENV MYSQL_USER=root
ENV MYSQL_PASSWORD=root
ENV MYSQL_DB=test_meli
ENV USERNAME=root

CMD ["python", "app.py"]