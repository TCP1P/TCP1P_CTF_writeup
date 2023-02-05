#!/bin/bash
export name="honksay"
export port="9988"
docker rm -f $name
docker build --tag=$name .
docker run -p $port:$port --rm --name=$name $name