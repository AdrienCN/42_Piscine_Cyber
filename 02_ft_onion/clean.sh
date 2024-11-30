#!/bin/bash

COLOR="\033[95m"
CLR_RST="\033[0m"
HDR="[42]"


P_HTTP_HOST="8080"
P_SSH_HOST="2121"

P_HTTP_CTNR="80"
P_SSH_CTNR="4242"

IMG_NAME=ft_onion


LINE() {
    local arg1="$1"
    printf "%b %s %b\n" "$HDR$COLOR" "$arg1" "$CLR_RST$HDR"
    }

LINE "[CLEANING]--------START----------[CLEANING]"

LINE "Clean all containers ? [y/n]"
read cleaning
if [ "$cleaning" = "y" ]; then 

LINE "Stopping all running containers..."
docker ps -q | xargs -r docker stop

# Remove all containers (stopped and running)
LINE "Removing all containers..."
docker ps -a -q | xargs -r docker rm
LINE "All containers stopped and removed. System cleaned!"
fi

# Clean existing image & container 
LINE "Clean all images ? [y/n]"
read cleaning
if [ "$cleaning" = "y" ]; then 
LINE "Removing all existing docker images"
docker image prune -a -f
fi
LINE "[CLEANING]--------END----------[CLEANING]"
printf "\n\n"