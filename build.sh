#!/bin/bash

docker build -t image -f Dockerfile --rm . 
docker run --name  img -d image /bin/bash -c "while:; sleep 5; done" ; docker cp img://home/src/build/traceroute build/. ; docker rm -f img