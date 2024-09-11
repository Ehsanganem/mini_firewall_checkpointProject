#!/bin/bash
DOMAIN=$1
IPS=$(getent ahosts "$DOMAIN" | awk '{print $1}' | uniq)

if [ -z "$IPS" ]; then
    echo "No IP addresses found for $DOMAIN"
    exit 1
fi

for IP in $IPS; do
    echo "Blocking IP: $IP"
    echo "add_ip $IP" > /proc/mini_firewall
done
