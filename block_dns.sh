#!/bin/bash

# The script takes one argument (the domain name) from the command line
DOMAIN=$1

# 'getent' command to resolve both IPv4 and IPv6 addresses for the given domain.
# 'awk' extracts only the IP addresses, ignoring other data, and 'uniq' removes any duplicates.
IPS=$(getent ahosts "$DOMAIN" | awk '{print $1}' | uniq)

if [ -z "$IPS" ]; then
    echo "No IP addresses found for $DOMAIN"
    exit 1  
fi

# Loop through each IP address in the $IPS variable.
for IP in $IPS; do

    # Check if the IP is an IPv6 address. IPv6 addresses contain colons (':').
    if [[ $IP == *:* ]]; then
        echo "Blocking IPv6: $IP"
        
        # Add a rule using 'ip6tables' to block incoming packets from the specified IPv6 address.
        sudo ip6tables -A INPUT -s $IP -j DROP
        
        # Add a rule using 'ip6tables' to block outgoing packets to the specified IPv6 address.
        sudo ip6tables -A OUTPUT -d $IP -j DROP
    else
        echo "Blocking IPv4: $IP"
        sudo iptables -A INPUT -s $IP -j DROP
        
        # Add a rule using 'iptables' to block outgoing packets to the specified IPv4 address.
        sudo iptables -A OUTPUT -d $IP -j DROP
    fi
done
