#!/bin/bash

#  Make sure docker image is called myapp

docker run -m 64m --memory-swap 64m \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -p 8501:8501 \
    --name demoweb \
    -it myapp /bin/bash 