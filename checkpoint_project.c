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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ehsan and Paz");
MODULE_DESCRIPTION("Checkpoint kernel project with Netfilter hook");
MODULE_VERSION("1.0");

struct blocked_ip {
    __be32 ip;
    struct list_head list;
};

static LIST_HEAD(blocked_ip_list);

#define BLOCKED_IP "192.168.33.129"

unsigned int block_ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

//
//  HOOK SET UP
//

// Netfilter hook
static struct nf_hook_ops pre_routing_hook;

// Hook function
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
        return NF_DROP;
    }

    return NF_ACCEPT;
}

void add_blocked_ip(const char *ip_str) {
    struct blocked_ip *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    
    if (!new_node)
        return;

    new_node->ip = in_aton(ip_str);

    INIT_LIST_HEAD(&new_node->list);
    list_add(&new_node>list, &blocked_ip_list);
}

void hook_init(){
    // Fill hook struct fields.
    pre_routing_hook.hook = block_ip_hook; // Hook function
    pre_routing_hook.hooknum = NF_INET_PRE_ROUTING; // Stage
    pre_routing_hook.pf = PF_INET; // protocol (IPV4)
    pre_routing_hook.priority = NF_IP_PRI_FIRST;
}

//
//  END HOOK SET UP
//


//
// MODULE SET UP
//

static int __init checkpoint_init(void) {
    printk(KERN_INFO "Kernel project started\n");
    
    hook_init();

    // Register the hook
    nf_register_net_hook(&init_net, &pre_routing_hook);

    return 0;
}

static void __exit checkpoint_exit(void) {
    printk(KERN_INFO "G00D but not bye!\n");

    // Unregister the Netfilter hook
    nf_unregister_net_hook(&init_net, &pre_routing_hook);
}

//
//  END MODULE SET UP
//

// Register the module's initialization and cleanup functions
module_init(checkpoint_init);
module_exit(checkpoint_exit);
