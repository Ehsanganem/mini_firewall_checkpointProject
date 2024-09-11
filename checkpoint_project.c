#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>        
#include <linux/netfilter_ipv4.h>   
#include <linux/ip.h>               
#include <linux/timer.h>            
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>          // For procfs
#include <linux/uaccess.h>          // For copy_from_user

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ehsan and Paz");
MODULE_DESCRIPTION("Checkpoint kernel project with Netfilter hook and Procfs API");
MODULE_VERSION("1.0");

#define PROC_FILE "mini_firewall"

struct blocked_ip {
    __be32 ip;
    struct list_head list;
};

static LIST_HEAD(blocked_ip_list);

unsigned int block_ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

//
//  HOOK FUNCTION
//

// Netfilter hook
static struct nf_hook_ops pre_routing_hook;

// Hook main function
unsigned int block_ip_hook(void *priv,
                           struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct blocked_ip *entry;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);

    if (!ip_header)
        return NF_ACCEPT;

    // Iterate through the blocked IP list and check if the packet source IP matches
    list_for_each_entry(entry, &blocked_ip_list, list) {
        if (ip_header->saddr == entry->ip) {
            printk(KERN_INFO "Blocked packet from %pI4\n", &ip_header->saddr);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

void free_blocked_ips(void) {
    struct blocked_ip *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &blocked_ip_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

void add_blocked_ip(const char *ip_str) {
    struct blocked_ip *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    
    if (!new_node)
        return;

    new_node->ip = in_aton(ip_str);

    INIT_LIST_HEAD(&new_node->list);
    list_add(&new_node->list, &blocked_ip_list);
}

void remove_blocked_ip(const char *ip_str) {
    struct blocked_ip *entry, *tmp;
    __be32 ip = in_aton(ip_str);

    list_for_each_entry_safe(entry, tmp, &blocked_ip_list, list) {
        if (entry->ip == ip) {
            list_del(&entry->list);
            kfree(entry);
            printk(KERN_INFO "Removed IP %s from blocklist\n", ip_str);
            return;
        }
    }
    printk(KERN_INFO "IP %s not found in blocklist\n", ip_str);
}

void display_blocked_ips(void) {
    struct blocked_ip *entry;

    printk(KERN_INFO "Blocked IPs:\n");
    list_for_each_entry(entry, &blocked_ip_list, list) {
        printk(KERN_INFO "%pI4\n", &entry->ip);
    }
}

// Procfs Write Function
ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char command[256];

    if (count > 255)
        return -EINVAL;

    if (copy_from_user(command, buffer, count))
        return -EFAULT;

    command[count] = '\0'; // Null terminate the string

    // Parse the user commands
    if (strstr(command, "add_ip")) {
        char *ip_str = strchr(command, ' ') + 1;
        add_blocked_ip(ip_str);
        printk(KERN_INFO "Added IP to blocklist: %s\n", ip_str);
    } else if (strstr(command, "remove_ip")) {
        char *ip_str = strchr(command, ' ') + 1;
        remove_blocked_ip(ip_str);
        printk(KERN_INFO "Removed IP from blocklist: %s\n", ip_str);
    } else if (strstr(command, "list_ips")) {
        display_blocked_ips();
    } else if (strstr(command, "help")) {
        printk(KERN_INFO "Available commands:\n");
        printk(KERN_INFO "add_ip <IP> - Add IP to blocklist\n");
        printk(KERN_INFO "remove_ip <IP> - Remove IP from blocklist\n");
        printk(KERN_INFO "list_ips - Show all blocked IPs\n");
    } else {
        printk(KERN_INFO "Unknown command. Use 'help' for a list of available commands.\n");
    }

    return count;
}
static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *pos) {
    char *output;
    int len = 0;
    struct blocked_ip *entry;

    if (*pos > 0) // If offset is non-zero, return 0 to indicate end of file
        return 0;

    // Allocate memory for the output
    output = kmalloc(4096, GFP_KERNEL); 
    if (!output)
        return -ENOMEM;

    len += sprintf(output, "Blocked IPs:\n");
    
    if (list_empty(&blocked_ip_list)) {
        len += sprintf(output + len, "No blocked IPs.\n");
    } else {
        list_for_each_entry(entry, &blocked_ip_list, list) {
            len += sprintf(output + len, "%pI4\n", &entry->ip);
        }
    }

    if (copy_to_user(buffer, output, len)) {
        kfree(output);
        return -EFAULT;
    }

    *pos = len;
    kfree(output);
    return len;
}

// Update proc operations to include both read and write
static const struct proc_ops proc_file_ops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

//
// MODULE SET UP
//

static int __init checkpoint_init(void) {
    printk(KERN_INFO "IP BLOCKER LUNCHED\n");

    // Create proc file
    if (!proc_create(PROC_FILE, 0666, NULL, &proc_file_ops)) {
        printk(KERN_ERR "Error: Could not initialize /proc/%s\n", PROC_FILE);
        return -ENOMEM;
    }

    // Hook Init
    pre_routing_hook.hook = block_ip_hook;
    pre_routing_hook.hooknum = NF_INET_PRE_ROUTING;
    pre_routing_hook.pf = PF_INET;
    pre_routing_hook.priority = NF_IP_PRI_FIRST;

    // Register the hook
    nf_register_net_hook(&init_net, &pre_routing_hook);

    // Add some example IPs
    add_blocked_ip("13.226.2.101"); // Example blocked IP
    add_blocked_ip("13.226.2.6");
    add_blocked_ip("13.226.2.94");

    return 0;
}

static void __exit checkpoint_exit(void) {
    printk(KERN_INFO "G00D but not bye!\n");

    // Remove proc file
    remove_proc_entry(PROC_FILE, NULL);

    // Unregister the Netfilter hook
    nf_unregister_net_hook(&init_net, &pre_routing_hook);
    // Free the blocked IPs
    free_blocked_ips();
    
}
// Register the module's initialization and cleanup functions
module_init(checkpoint_init);
module_exit(checkpoint_exit);
