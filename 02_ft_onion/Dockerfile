# syntax=docker/dockerfile:1
FROM debian:bookworm

# Install web server & configuration necessary packages
RUN     apt-get update  &&                      \
        apt-get install nginx                   \
                        wget                    \
                        gpg                     \
                        apt-transport-https     \
                        -y

#DEBUG [TO DELETE]                  
RUN apt-get install vim -y

# INSTALL TOR :
        # Configure local repository to be able to download TOR see official docs -> "https://support.torproject.org/apt/tor-deb-repo/"
RUN    echo "deb  [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" >> /etc/apt/sources.list.d/tor.list
RUN    wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | tee /usr/share/keyrings/deb.torproject.org-keyring.gpg >/dev/null
        # Actually install TOR
RUN    apt-get update && apt-get install tor -y

# SETUP HIDDEN SERVICE :
        # Replace default config files by customs + starter scripts
COPY    config/my_index.html    /var/www/html/index.nginx-debian.html
COPY    config/my_torrc         /etc/tor/torrc
COPY    config/my_nginx.conf    /etc/nginx/nginx.conf

RUN     service tor start

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]