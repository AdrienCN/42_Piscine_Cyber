
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
echo "Connect ssh  via :\"ssh -p 2121 root@localhost\""
LINE "Use the Onion URL in a TOR browser : $BLUE$(cat /var/lib/tor/hidden_service/hostname)$CLR_RST"
service tor start
service nginx restart
service ssh start -D