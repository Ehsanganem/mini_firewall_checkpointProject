# **Mini Firewall with VPN-like IP Masking**

## **Project Overview**

The **Mini Firewall** is a Linux kernel module that provides basic firewall capabilities. It supports blocking specific IP addresses (both IPv4 and IPv6), blocking domains via DNS resolution, and implementing a **VPN-like IP masking** feature to anonymize network traffic by masking the real source IP address. This project is designed for Linux systems and includes a simple interface via the `/proc` filesystem for user interaction.

The project also comes with a **bash script** to manage and control the firewall and masking functionalities interactively.

## **Key Features**

- **Block IPv4/IPv6 traffic:** You can block traffic from/to specific IP addresses.
- **Domain-based blocking:** Resolve domain names to their associated IPs and block them.
- **VPN-like IP masking:** Mask your real IP with a fake one for outgoing packets.
- **Dynamic configuration:** Add and remove IP addresses from the blocklist dynamically using the `/proc` file system.
- **Simple bash control script:** A user-friendly script to manage the firewall operations via a menu system.
- **Kernel logging:** Packet blocking and masking operations are logged in the kernel messages for easy tracking.

## **How It Works**

- The firewall operates at the network level, hooking into the Linux **Netfilter** framework.
- For each incoming and outgoing packet, the firewall checks if the source or destination IP matches any in the blocklist and drops the packet if there is a match.
- The **VPN-like masking** feature changes the source IP of outgoing packets to a predefined masked IP (e.g., `192.168.1.1` for IPv4).
- Users interact with the firewall through the `/proc/mini_firewall` file, which accepts commands to block or unblock IPs, and to enable or disable VPN-like masking.
- A bash script is provided to automate these operations with an easy-to-use menu interface.

## **Requirements**

- Linux operating system with kernel development headers installed.
- **iptables** and **ip6tables** utilities for managing network traffic.
- Basic familiarity with Linux command-line operations and network configurations.

## **Installation**

### 1. **Clone the Repository**

```bash
git clone https://github.com/yourusername/your-repo.git
cd your-repo
