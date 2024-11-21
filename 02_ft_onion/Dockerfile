# syntax=docker/dockerfile:1
FROM debian:bookworm



# Install web server & configuration necessary packages
RUN     apt-get update  &&                      \
        apt-get install nginx                   \
                        wget                    \
                        gpg                     \
                        apt-transport-https     \
                        -y


# Configure local repository to be able to download TOR
RUN    echo "deb  [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" >> /etc/apt/sources.list.d/tor.list 
RUN    wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | tee /usr/share/keyrings/deb.torproject.org-keyring.gpg >/dev/null


# Now we can install tor from the updated repo
RUN    apt-get update && apt-get install tor

EXPOSE 8000

CMD ["nginx", "-g", "daemon off;"]