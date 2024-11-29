#!/bin/bash

#  Make sure docker image is called myapp

docker run -m 64m --memory-swap 64m \
    -p 8500:8500 \
    --name demoweb \
    -it myapp /bin/bash 