#!/bin/bash
MY_PORT=$1
REMOTE_IP=$2
REMOTE_PORT=$3

# OSが自動送信するRSTパケットを破棄(DROP)するルールを追加
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport $MY_PORT --dport $REMOTE_PORT -d $REMOTE_IP -j DROP