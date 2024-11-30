
HDR="[42]"
HDR_END="$HDR"
BLUE="\033[34m"
CLR_RST="\033[0m"

LINE() {
    local arg1="$1"
    echo -e "$HDR $arg1 $HDR_END"
}

echo "root:adminadmin" | chpasswd
echo "ssh user=root"
echo "password=adminadmin"
echo "Connect ssh  via :\"ssh -i .ssh/onion_ed25519-p 2121 root@localhost\""
LINE "Onion URL : $BLUE$(cat /var/lib/tor/hidden_service/hostname)$CLR_RST"
LINE "Please use the Onion URL in a TOR browser"
service tor start
#service ssh start -D
service ssh start
service nginx start
sleep infinity