#!/bin/bash

#  Make sure docker image is called myapp

# Use host.docker.internal to reach the host machine on macOS
docker run -m 64m --memory-swap 64m \
    -p 8500:8500 \
    --add-host=host.docker.internal:host-gateway \
    --name demoweb \
    -it myapp /bin/bash 