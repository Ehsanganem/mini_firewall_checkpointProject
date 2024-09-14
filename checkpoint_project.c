#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/inet.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ehsan and Paz");
MODULE_DESCRIPTION("Mini Firewall with Domain Blocking via DNS and VPN-like IP Masking");
MODULE_VERSION("1.3");

#define PROC_FILE "mini_firewall"

static bool vpn_enabled = false;  // VPN-like masking flag
static __be32 user_real_ip;
static struct in6_addr user_real_ipv6;

// Blocked IP structures
struct blocked_ip {
    __be32 ip;
    struct list_head list;
};

struct blocked_ipv6 {
    struct in6_addr ip;
    struct list_head list;
};

static LIST_HEAD(blocked_ip_list);
static LIST_HEAD(blocked_ipv6_list);

// Function declarations
void add_blocked_ip(const char *ip_str);
void add_blocked_ipv6(const char *ip_str);
void remove_blocked_ip(const char *ip_str);
void remove_blocked_ipv6(const char *ip_str);

unsigned int block_ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int block_ipv6_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int vpn_mask_ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// Hook structures for IPv4 and IPv6
static struct nf_hook_ops pre_routing_hook;
static struct nf_hook_ops ipv6_pre_routing_hook;
static struct nf_hook_ops vpn_masking_hook;  // Added explicit declaration

// Blocking IPv4 addresses
unsigned int block_ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct blocked_ip *block_entry;

    if (!skb) return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;

    list_for_each_entry(block_entry, &blocked_ip_list, list) {
        if (ip_header->saddr == block_entry->ip || ip_header->daddr == block_entry->ip) {
            printk(KERN_INFO "Blocked IPv4 packet from/to: %pI4\n", &ip_header->saddr);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// Blocking IPv6 addresses
unsigned int block_ipv6_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ipv6hdr *ipv6_header;
    struct blocked_ipv6 *block_entry;

    if (!skb) return NF_ACCEPT;

    ipv6_header = ipv6_hdr(skb);
    if (!ipv6_header) return NF_ACCEPT;

    list_for_each_entry(block_entry, &blocked_ipv6_list, list) {
        if (ipv6_addr_cmp(&ipv6_header->saddr, &block_entry->ip) == 0 ||
            ipv6_addr_cmp(&ipv6_header->daddr, &block_entry->ip) == 0) {
            printk(KERN_INFO "Blocked IPv6 packet from/to: %pI6c\n", &ipv6_header->saddr);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// VPN-like IP masking functionality
unsigned int vpn_mask_ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (vpn_enabled) {
        struct iphdr *ip_header = ip_hdr(skb);
        if (ip_header && ip_header->saddr == user_real_ip) {
            // Mask the real IP with a fake one (for IPv4)
            ip_header->saddr = htonl(0xC0A80101);  // Masked IP as 192.168.1.1
            printk(KERN_INFO "Masked IPv4 packet from: %pI4\n", &ip_header->saddr);
        }

        struct ipv6hdr *ipv6_header = ipv6_hdr(skb);
        if (ipv6_header && ipv6_addr_cmp(&ipv6_header->saddr, &user_real_ipv6) == 0) {
            // Mask the real IPv6 with a fake one (for IPv6)
            struct in6_addr masked_ipv6 = IN6ADDR_LOOPBACK_INIT;  // Example mask
            ipv6_header->saddr = masked_ipv6;
            printk(KERN_INFO "Masked IPv6 packet from: %pI6c\n", &ipv6_header->saddr);
        }
    }
    return NF_ACCEPT;
}

// Adding/removing IPs via procfs
ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    char user_buffer[128];
    if (copy_from_user(user_buffer, buffer, count))
        return -EFAULT;
    user_buffer[count] = '\0';

    if (strncmp(user_buffer, "add_ip", 6) == 0) {
        char ip_str[16];
        sscanf(user_buffer + 7, "%s", ip_str);
        add_blocked_ip(ip_str);
    } else if (strncmp(user_buffer, "add_ipv6", 8) == 0) {
        char ipv6_str[INET6_ADDRSTRLEN];
        sscanf(user_buffer + 9, "%s", ipv6_str);
        add_blocked_ipv6(ipv6_str);
    } else if (strncmp(user_buffer, "remove_ip", 9) == 0) {
        char ip_str[16];
        sscanf(user_buffer + 10, "%s", ip_str);
        remove_blocked_ip(ip_str);
    } else if (strncmp(user_buffer, "remove_ipv6", 11) == 0) {
        char ipv6_str[INET6_ADDRSTRLEN];
        sscanf(user_buffer + 12, "%s", ipv6_str);
        remove_blocked_ipv6(ipv6_str);
    } else if (strncmp(user_buffer, "vpn_enable", 10) == 0) {
        sscanf(user_buffer + 11, "%pI4", &user_real_ip);
        vpn_enabled = true;
        printk(KERN_INFO "VPN-like IP masking enabled for IP: %pI4\n", &user_real_ip);
    } else if (strncmp(user_buffer, "vpn_disable", 11) == 0) {
        vpn_enabled = false;
        printk(KERN_INFO "VPN-like IP masking disabled.\n");
    }

    return count;
}

// Proc operations for procfs
static const struct proc_ops proc_file_ops = {
    .proc_write = proc_write,
};

// Module initialization
static int __init mini_firewall_init(void) {
    // Register IPv4 and IPv6 hooks
    pre_routing_hook.hook = block_ip_hook;
    pre_routing_hook.pf = NFPROTO_IPV4;
    pre_routing_hook.hooknum = NF_INET_PRE_ROUTING;
    pre_routing_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &pre_routing_hook);

    ipv6_pre_routing_hook.hook = block_ipv6_hook;
    ipv6_pre_routing_hook.pf = NFPROTO_IPV6;
    ipv6_pre_routing_hook.hooknum = NF_INET_PRE_ROUTING;
    ipv6_pre_routing_hook.priority = NF_IP6_PRI_FIRST;
    nf_register_net_hook(&init_net, &ipv6_pre_routing_hook);

    // Register the VPN masking hook for IPv4
    vpn_masking_hook.hook = vpn_mask_ip_hook;
    vpn_masking_hook.pf = NFPROTO_IPV4;
    vpn_masking_hook.hooknum = NF_INET_PRE_ROUTING;
    vpn_masking_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &vpn_masking_hook);

    // Create proc entry
    proc_create(PROC_FILE, 0666, NULL, &proc_file_ops);
    printk(KERN_INFO "Mini Firewall with VPN-like IP masking loaded.\n");
    return 0;
}

// Module exit
static void __exit mini_firewall_exit(void) {
    nf_unregister_net_hook(&init_net, &pre_routing_hook);
    nf_unregister_net_hook(&init_net, &ipv6_pre_routing_hook);
    nf_unregister_net_hook(&init_net, &vpn_masking_hook);
    remove_proc_entry(PROC_FILE, NULL);
    printk(KERN_INFO "Mini Firewall unloaded.\n");
}

module_init(mini_firewall_init);
module_exit(mini_firewall_exit);
