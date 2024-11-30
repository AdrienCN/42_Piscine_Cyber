# syntax=docker/dockerfile:1
FROM debian:bookworm

# Install web server & configuration necessary packages
RUN     apt-get update  &&                      \
        apt-get install nginx                   \
                        wget                    \
                        gpg                     \
                        apt-transport-https     \
                        openssh-server          \
                        vim                     \
                        -y
                        
#RUN     mkdir -p /root/.ssh
#COPY    .ssh_onion/onion_ed25519.pub    /root/.ssh/authorized_keys
#RUN     useradd ssh_user_onion
#RUN     chown ssh_user_onion /root/.ssh/authorized_keys
#RUN     chmod 600 /root/.ssh/authorized_keys

RUN     groupadd sshgroup && \
	useradd -ms /bin/bash -g sshgroup sshuser && \
	mkdir -p /home/sshuser/.ssh

COPY    .ssh_onion/onion_ed25519.pub    /home/sshuser/.ssh/authorized_keys

RUN     chown sshuser:sshgroup /home/sshuser/.ssh/authorized_keys && \
	chmod 600 /home/sshuser/.ssh/authorized_keys

RUN     service ssh start

# INSTALL TOR :
# Configure local repository to be able to download TOR see official docs -> "https://support.torproject.org/apt/tor-deb-repo/"
RUN <<EOF
echo "deb  [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" >> /etc/apt/sources.list.d/tor.list;
wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | tee /usr/share/keyrings/deb.torproject.org-keyring.gpg >/dev/null;
        # Actually install TOR
apt-get update && apt-get install tor -y;
EOF

# SETUP HIDDEN SERVICE :
# Replace default config files by customs + starter scripts

COPY    config/my_index.html            /var/www/html/index.nginx-debian.html
COPY    config/my_torrc                 /etc/tor/torrc
COPY    config/my_nginx.conf            /etc/nginx/nginx.conf
COPY    config/my_sshd_config           /etc/ssh/sshd_config
COPY    scripts/ft_onion_starter.sh     .

# Setup TOR filesystem and permission
RUN     service tor start

EXPOSE 80 4242

ENTRYPOINT ["/bin/bash", "./ft_onion_starter.sh"]