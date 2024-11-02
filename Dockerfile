FROM python:3.11-slim

WORKDIR /my_container
COPY . /my_container

RUN pip3 install -r requirements.txt

EXPOSE 8501

