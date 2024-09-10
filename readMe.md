            *-------------------Protection feature--------------------*

    our protection approach is Dynamic IP Address Filtering which means:
    block or allow traffic from specific IP addresses. This is useful for preventing unwanted or malicious traffic from known IP addresses, such as blocking access from specific attackers or countries.
    when traffic comes from a certain ip address our kernel checks if the ip address is in the block list if it is we drop the package.


            *-------------Which Hook is Used and Why?---------------*

    we used the NF_INET_PRE_ROUTING(pre-routing-hook) hook to intercept network packets, pre-routing hook is triggered immediately after the packet arrives at the network interface but before the kernel determines whether the packet is destined for the local machine or needs to be forwarded to another network.

    This early stage is ideal for blocking or filtering traffic since it ensures that malicious or unwanted packets are dropped before they are processed further by the system. This reduces the overall load on the system as unwanted traffic is discarded right at the entry point.

    Early interception of network traffic allows  to block traffic based on the IP address before it can exploit any potential vulnerabilities in services running on the system.
   
    
