FROM python:3.11-slim

# Install necessary tools for VS Code remote development
RUN apt-get update && \
    apt-get install -y \
        nano \
        gcc \
        libpcap-dev

WORKDIR /home
COPY . /home

RUN gcc -o bin/packet_sniffer2 src/main.c -lpcap
RUN pip3 install -r other/utils/requirements.txt

# Add Docker socket mount point
VOLUME /var/run/docker.sock
# Add volume for code persistence
VOLUME /home

EXPOSE 8501
