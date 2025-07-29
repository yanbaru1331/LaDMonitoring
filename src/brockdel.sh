#!/bin/bash
MY_PORT=$1
REMOTE_IP=$2
REMOTE_PORT=$3

sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport $MY_PORT --dport $REMOTE_PORT -d $REMOTE_IP -j DROP