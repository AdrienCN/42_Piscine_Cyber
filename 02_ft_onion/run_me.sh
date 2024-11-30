#!/bin/bash

COLOR="\033[95m"
CLR_RST="\033[0m"
HDR="$MAGENTA[42]"
HDR_END="$HDR$CLR_RST"


P_HTTP_HOST="8080"
P_SSH_HOST="2121"

P_HTTP_CTNR="80"
P_SSH_CTNR="4242"

IMG_NAME=ft_onion


LINE() {
    local arg1="$1"
    printf "%b %s %b\n" "$HDR$COLOR" "$arg1" "$CLR_RST$HDR"
    }


# Build docker image  
LINE "Do you want build an $IMG_NAME image ? [y/n]"
read answer
if [ "$answer" = "y" ]; then 
LINE "Building docker image [ft_onion] ...."
docker build -t $IMG_NAME .
fi

# Run docker 
LINE "Do you want to run the container from $IMG_NAME image ? [y/n]"
read answer
if [ "$answer" = "y" ]; then 
LINE "Start docker container from [ft_onion] image in detached mode ...."
docker run -d -p $P_HTTP_HOST:$P_HTTP_CTNR -p $P_SSH_HOST:$P_SSH_CTNR $IMG_NAME
docker ps -q | xargs -r docker logs
fi

LINE "Thanks goodbye"
