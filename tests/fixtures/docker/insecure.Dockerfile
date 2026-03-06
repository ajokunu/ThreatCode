FROM ubuntu:latest

ARG DB_PASSWORD=secret123

ENV API_KEY=my-secret-key

RUN apt-get update && apt-get install -y openssh-server curl

RUN curl https://example.com/install.sh | bash

RUN sudo chmod 777 /app

ADD local_file.tar.gz /app/
ADD id_rsa /root/.ssh/

COPY server.key /etc/ssl/
COPY app.py /app/

EXPOSE 22
EXPOSE 80
EXPOSE 443

ENTRYPOINT ["python"]
CMD ["app.py"]
