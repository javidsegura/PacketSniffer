FROM python:3.11-slim

# Install necessary tools for VS Code remote development
RUN apt-get update && \
    apt-get install -y \
        nano \
        gcc \
        libpcap-dev

WORKDIR /home
COPY . /home

# RUN gcc -o bin/packet_sniffer2 src/main.c -lpcap
RUN pip3 install -r requirements.txt --no-cache-dir

EXPOSE 8501
