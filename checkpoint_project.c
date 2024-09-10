#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>        // For Netfilter hooks
#include <linux/netfilter_ipv4.h>   // For IPv4 hooks
#include <linux/ip.h>               // For IP header
#include <linux/timer.h>            // For timers
#include <linux/inet.h>             // For in_aton()

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ehsan");
MODULE_DESCRIPTION("Checkpoint kernel project with Netfilter hook");
MODULE_VERSION("1.0");

#define BLOCKED_IP "192.168.33.129"  // Use your own IP address
  // Example IP to block

// Forward declarations for the functions
unsigned int block_ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void print_hook_message(struct timer_list *t);

// Netfilter hook
static struct nf_hook_ops pre_routing_hook;
static struct timer_list my_timer;

// Function to block traffic from a specific IP
unsigned int block_ip_hook(void *priv,
                           struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    struct iphdr *ip_header;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);  // Get the IP header

    if (ip_header && ip_header->saddr == in_aton(BLOCKED_IP)) {
        printk(KERN_INFO "Blocked packet from %pI4\n", &ip_header->saddr);
        return NF_DROP;  // Drop the packet
    }

    return NF_ACCEPT;  // Accept the packet if it's not from the blocked IP
}

// Timer function that prints a message every 10 seconds
void print_hook_message(struct timer_list *t)
{
    printk(KERN_INFO "Kernel module in Netfilter hook (NF_INET_PRE_ROUTING).\n");
    mod_timer(&my_timer, jiffies + 10 * HZ);  // Re-enable the timer for another 10 seconds
}

// Initialization function
static int __init checkpoint_init(void) {
    printk(KERN_INFO "Kernel project started\n");

    // Register the Netfilter hook for NF_INET_PRE_ROUTING
    pre_routing_hook.hook = block_ip_hook;
    pre_routing_hook.hooknum = NF_INET_PRE_ROUTING;
    pre_routing_hook.pf = PF_INET;
    pre_routing_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &pre_routing_hook);

    // Initialize and start the timer
    timer_setup(&my_timer, print_hook_message, 0);
    mod_timer(&my_timer, jiffies + 10 * HZ);  // Set the timer to run every 10 seconds

    return 0;
}

// Exit function
static void __exit checkpoint_exit(void) {
    printk(KERN_INFO "G00D but not bye!\n");

    // Unregister the Netfilter hook
    nf_unregister_net_hook(&init_net, &pre_routing_hook);

    // Delete the timer
    del_timer(&my_timer);
}

// Register the module's initialization and cleanup functions
module_init(checkpoint_init);
module_exit(checkpoint_exit);
