#!/bin/bash

#docker run -m 256m --memory-swap 256m -p 8501:8501 myapp # weak memory

docker run -v /var/run/docker.sock:/var/run/docker.sock -p 8501:8501 --name demoweb -it  weakapp_img /bin/bash 