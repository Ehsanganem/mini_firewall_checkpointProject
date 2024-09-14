#!/bin/bash

while true; do
    echo "Mini Firewall Menu:"
    echo "1. Add IP to blocklist"
    echo "2. Remove IP from blocklist"
    echo "3. List blocked IPs"
    echo "4. Block domain by DNS"
    echo "5. Enable VPN-like IP masking"
    echo "6. Disable VPN-like IP masking"
    echo "7. Help"
    echo "8. Exit"
    read -p "Select an option: " option

    case $option in
        1)
            # Add IP to blocklist (IPv4 or IPv6)
            echo "Enter the IP address (IPv4 or IPv6) to block:"
            read ip
            if [[ $ip == *:* ]]; then
                echo "add_ipv6 $ip" > /proc/mini_firewall
            else
                echo "add_ip $ip" > /proc/mini_firewall
            fi
            ;;
        2)
            # Remove IP from blocklist (IPv4 or IPv6)
            echo "Enter the IP address (IPv4 or IPv6) to remove:"
            read ip
            if [[ $ip == *:* ]]; then
                echo "remove_ipv6 $ip" > /proc/mini_firewall
            else
                echo "remove_ip $ip" > /proc/mini_firewall
            fi
            ;;
        3)
            # List all blocked IPs
            echo "Listing blocked IPs:"
            cat /proc/mini_firewall
            ;;
        4)
            # Block domain by DNS
            echo "Enter the domain name to block (DNS):"
            read domain
            if [ -z "$domain" ]; then
                echo "Error: Domain name cannot be empty!"
            else
                ./block_dns.sh "$domain"
            fi
            ;;
        5)
            # Enable VPN-like IP masking
            echo "Enter your real IP address to mask (IPv4 only):"
            read user_ip
            echo "vpn_enable $user_ip" > /proc/mini_firewall
            ;;
        6)
            # Disable VPN-like IP masking
            echo "Disabling VPN-like IP masking..."
            echo "vpn_disable" > /proc/mini_firewall
            ;;
        7)
            # Display help information
            echo "Help section:"
            echo "1. Add IP to blocklist: Blocks the specified IP."
            echo "2. Remove IP from blocklist: Removes the specified IP from blocklist."
            echo "3. List blocked IPs: Lists all currently blocked IPs."
            echo "4. Block domain (DNS): Blocks all IPs associated with the provided domain."
            echo "5. Enable VPN-like IP masking: Masks your real IP with a fake one."
            echo "6. Disable VPN-like IP masking: Disables the VPN-like IP masking feature."
            echo "7. Help: Displays this help menu."
            echo "8. Exit: Exits the firewall menu."
            ;;
        8)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please choose a valid option."
            ;;
    esac
done
