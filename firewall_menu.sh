#!/bin/bash

while true; do
    echo "==================================="
    echo "      Mini Firewall - IP Blocker"
    echo "==================================="
    echo "1. Add IP to blocklist"
    echo "2. Remove IP from blocklist"
    echo "3. List blocked IPs"
    echo "4. Block domain (DNS)"
    echo "5. Help"
    echo "6. Exit"
    echo -n "Choose an option: "

    read choice

    case $choice in
        1)
            echo "Enter the IP to block:"
            read ip
            echo "add_ip $ip" > /proc/mini_firewall
            ;;
        2)
            echo "Enter the IP to remove:"
            read ip
            echo "remove_ip $ip" > /proc/mini_firewall
            ;;
        3)
            # List all blocked IPs from /proc/mini_firewall
            echo "Listing blocked IPs:"
            if cat /proc/mini_firewall; then
                echo "Blocked IPs listed."
            else
                echo "Failed to read /proc/mini_firewall."
            fi
            ;;
        4)
            echo "Enter the domain name to block (DNS):"
            read domain
            ./block_dns.sh "$domain"
            ;;
        5)
            echo "Help section:"
            echo "add_ip <IP> - Add IP to blocklist"
            echo "remove_ip <IP> - Remove IP from blocklist"
            echo "list_ips - List blocked IPs"
            echo "block_domain <Domain> - Block all IPs of a domain"
            ;;
        6)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please choose a valid option."
            ;;
    esac
done
