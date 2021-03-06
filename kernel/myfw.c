#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/if_arp.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_bridge.h>
#include <linux/time.h>
#include <linux/timer.h>

//常量定义
#define CDEV_NAME "myfw"
#define CLASS_NAME "myfw"

#ifndef __FW_INCLUDE__
#define __FW_INCLUDE__


//对规则链表的操作
#define FW_ADD_RULE 0
#define FW_DEL_RULE 1
#define FW_CLEAR_RULE 3
#define FW_SET_HOST_IP 4
#define FW_SET_HOST_NETMASK 5
#define FW_GET_LINK_NUM 6
#define FW_GET_LINK_LIST 7
#define FW_SET_DEFAULT_RULE 8
#define FW_GET_LOG_NUM 9
#define FW_GET_LOG_LIST 10
#define FW_START_NAT 11
#define FW_STOP_NAT 12
#define FW_GET_NAT_NUM 13
#define FW_GET_NAT_LIST 14
#define FW_SET_HOST_IP_OUT 15

#endif

//模块信息
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("lxb, HUST IS1602");
MODULE_DESCRIPTION("A simple firewall");
MODULE_VERSION("1.0.0");

//防火墙规则定义
typedef struct Node
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    unsigned short protocol;
    unsigned short sMask;
    unsigned short dMask;
    bool isPermit;
    bool isLog;
    struct Node *next; //单链表的指针域
} Node, *NodePointer;

//源NAT规则定义
typedef struct NatNode
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    struct NatNode *next;
} NatNode, *NatNodePointer;

//连接定义
typedef struct LinkNode
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    time_t start; //连接开始时的linux时间,超时1分钟,则断开连接
    unsigned int lifetime;
    struct LinkNode *next;
} LinkNode, *LinkNodePointer;

//
typedef struct LogNode
{
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;

    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    unsigned short protocol;

    unsigned int rule_sip;
    unsigned int rule_dip;
    unsigned short rule_sport;
    unsigned short rule_dport;
    unsigned short rule_protocol;
    bool rule_permit;

    struct LogNode *next;
} LogNode, *LogNodePointer;

/*全局变量定义*/
int major_number = 0; //主设备号
int minor_number = 0;
struct device *device;
struct class *class;
static struct cdev netfilter_cdev; //字符设备定义

static NodePointer lheader, ltail;     //规则链表的头指针与尾指针，该链表为带表头的链表，即lheader->next为第一个链表节点
static NatNodePointer nheader, ntail;  //NAT规则头指针与尾指针
static LinkNodePointer kheader, ktail; //连接表头指针与尾指针
static LogNodePointer gheader, gtail;  //

static struct timer_list tm; //定时器相关
struct timeval oldtv;

static unsigned int default_rule = NF_ACCEPT;

unsigned int hostIP, hostIP_out;
unsigned int hostnetmask;
unsigned int disport = 18000; //用于分配给NAT规则的端口号，从端口18000开始，每多一条规则，加1

bool nat_ctl_signal = false;

/*函数声明*/
//字符设备操作函数
static long netfilter_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg); //字符设备IO操作
static int netfilter_cdev_open(struct inode *inode, struct file *file);                   //字符设备打开
static int netfilter_cdev_release(struct inode *inode, struct file *file);                //字符设备释放

//规则链表处理函数
void add_firewall_node(struct Node *newnode);
void delete_firewall_node(struct Node *);
void clear_firewall_node(void);
void add_nat_node(NatNode *newnode);
void add_link_node(Node *newnode);
void delete_link_node(Node *tnode);
void add_log_node(Node *packageNode, Node *ruleNode);
void clear_log_node(void);
void clear_nat_node(void);

//初始化链表函数
void init_all_list(void);

//搜索规则函数
Node *find_firewall_node(Node *tnode);
bool find_dst_nat_node(NatNode *nnode);
bool find_src_nat_node(NatNode *nnode);
int find_link_node(Node *tnode);

//IP的字符串与数字相互转化函数
unsigned int get_uint_ip_addr(char *str);
char *get_string_ip_addr(unsigned int ip, char *sp, unsigned int len);

//各类协议的字符串与数字相互转化函数
char *getProtocolString(unsigned int protocol, char *sp, unsigned short len);
char *getPortString(unsigned short port, char *sp, unsigned short len);

//记录日志函数
void add_log_node(Node *packageNode, Node *ruleNode);

//定时检查函数，连接超时时断开连接
void time_func(unsigned long arg);

//hook函数
unsigned int hook_func_entry_nat(unsigned int hooknum,           //hook类型
                                 struct sk_buff *skb,            //数据包指针
                                 const struct net_device *in,    //数据包到达的接口
                                 const struct net_device *out,   //数据包离开的接口
                                 int (*okfn)(struct sk_buff *)); //一般在NF_STOLEN之前调用，在本实验中用处不大

unsigned int hook_func_firewall(unsigned int hooknum,
                                struct sk_buff *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn)(struct sk_buff *));

unsigned int hook_func_out_nat(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *));

//字符设备选项拿出需要的字段并且绑定相应的操作函数
struct file_operations netfilter_cdev_fops = {
    .owner = THIS_MODULE,                   //拥有该结构的模块的指针
    .unlocked_ioctl = netfilter_cdev_ioctl, //指定字符设备IO控制函数，老版本为.ioctl
    .open = netfilter_cdev_open,            //指定字符设备打开函数
    .release = netfilter_cdev_release       //指定字符设备释放函数
};

//hook函数选项设置，一进一出
struct nf_hook_ops hook_options_entry_nat = {
    .hook = hook_func_entry_nat,    //指定hook函数
    .hooknum = NF_INET_PRE_ROUTING, //指定hook类型
    .owner = THIS_MODULE,           //拥有该结构的模块的指针
    .pf = PF_INET,                  //协议簇，对于ipv4而言，是PF_INET
    .priority = NF_IP_PRI_NAT_DST   //优先级
};
struct nf_hook_ops hook_options_entry_firewall = {
    .hook = hook_func_firewall,
    .hooknum = NF_INET_PRE_ROUTING,
    .owner = THIS_MODULE,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FILTER};
struct nf_hook_ops hook_options_out_firewall = {
    .hook = hook_func_firewall,
    .hooknum = NF_INET_POST_ROUTING,
    .owner = THIS_MODULE,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FILTER};
struct nf_hook_ops hook_options_out_nat = {
    .hook = hook_func_out_nat,
    .hooknum = NF_INET_POST_ROUTING,
    .owner = THIS_MODULE,
    .pf = PF_INET,
    .priority = NF_IP_PRI_NAT_SRC};

/*字符设备操作函数*/
//打开设备
static int netfilter_cdev_open(struct inode *inode, struct file *file)
{
    printk("Device has been opened!\n");
    return 0;
}

//释放设备
static int netfilter_cdev_release(struct inode *inode, struct file *file)
{
    printk("Device has been closed!\n");
    return 0;
}

//IO控制，cmd为规则命令，即添加删除或清空
static long netfilter_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    Node tnode;
    char chostIP[20];
    char chostnetmask[20];
    char chostIP_out[20];
    LinkNode *knode;
    LogNode *gnode;
    NatNode *nnode;
    int temp;
    unsigned int link_pos, log_pos, nat_pos;
    switch (cmd)
    {
    case FW_ADD_RULE:
        copy_from_user(&tnode, (struct Node *)arg, sizeof(struct Node)); //从arg所指的用户空间中拷贝sizeof(struct Node)字节数的数据进入tnode所指的内核空间
        //printk("Get command FW_ADD_RULE!\n");
        add_firewall_node(&tnode);
        break;
    case FW_DEL_RULE:
        copy_from_user(&tnode, (struct Node *)arg, sizeof(struct Node));
        //printk("Get command FW_DEL_RULE\n");
        delete_firewall_node(&tnode);
        break;
    case FW_CLEAR_RULE:
        //printk("Get command FW_CLEAR_RULE\n");
        clear_firewall_node();
        break;
    case FW_SET_HOST_IP:
        copy_from_user(&hostIP, (unsigned int *)arg, sizeof(unsigned int));
        get_string_ip_addr(hostIP, chostIP, 20);
        //printk("HOST IP IS %s!!\n",chostIP);
        break;
    case FW_SET_HOST_NETMASK:
        copy_from_user(&hostnetmask, (unsigned int *)arg, sizeof(unsigned int));
        get_string_ip_addr(hostnetmask, chostnetmask, 20);
        //printk("HOST NETMASK IS %s!!\n",chostnetmask);
        break;
    case FW_SET_HOST_IP_OUT:
        copy_from_user(&hostIP_out, (unsigned int *)arg, sizeof(unsigned int));
        get_string_ip_addr(hostIP_out, chostIP_out, 20);
        //printk("HOST IP_OUT IS %s!!\n",chostIP_out);
        break;
    case FW_GET_LINK_NUM:
        copy_to_user((unsigned int *)arg, &(kheader->dip), sizeof(unsigned int));
        break;
    case FW_GET_LINK_LIST:
        knode = kheader;
        link_pos = 0;
        while (knode->next != NULL)
        {
            knode = knode->next;
            copy_to_user((LinkNode *)arg + link_pos, knode, sizeof(LinkNode));
            link_pos++;
        }
        break;
    case FW_SET_DEFAULT_RULE:
        copy_from_user(&temp, (int *)arg, sizeof(int));
        if (temp == 0)
        {
            default_rule = NF_ACCEPT;
            printk("default rule is accept\n");
        }
        else
        {
            default_rule = NF_DROP;
            printk("default rule is drop\n");
        }
        break;
    case FW_GET_LOG_NUM:
        copy_to_user((int *)arg, &(gheader->dip), sizeof(int));
        //printk("log num is %d!\n",gheader->dip);
        break;
    case FW_GET_LOG_LIST:
        //printk("LOG LIST has received!\n");
        gnode = gheader->next;
        log_pos = 0;
        while (gnode != NULL)
        {
            //printk("copying No.%d package!\n",log_pos);
            copy_to_user((LogNode *)arg + log_pos, gnode, sizeof(LogNode));
            log_pos++;
            gnode = gnode->next;
        }
        //printk("Copy is completed!\n");
        clear_log_node();
        break;
    case FW_START_NAT:
        nat_ctl_signal = true;
        break;
    case FW_STOP_NAT:
        nat_ctl_signal = false;
        clear_nat_node();
        break;
    case FW_GET_NAT_NUM:
        copy_to_user((int *)arg, &(nheader->dip), sizeof(int));
        break;
    case FW_GET_NAT_LIST:
        nnode = nheader->next;
        nat_pos = 0;
        while (nnode != NULL)
        {
            copy_to_user((NatNode *)arg + nat_pos, nnode, sizeof(NatNode));
            nat_pos++;
            nnode = nnode->next;
        }
        break;
    }

    return 0;
}

/*hook函数*/
unsigned int hook_func_firewall(unsigned int hooknum,
                                struct sk_buff *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn)(struct sk_buff *))
{

    //printk("hook_func_firewall!\n");
    unsigned int ret = default_rule; //默认接收

    struct iphdr *iph = ip_hdr(skb); //获取IP报文头部

    //如果数据包缓冲区为空或IP头为空，直接返回
    if (!skb || !iph)
    {
        return ret;
    }

    //检查IP报文头部中的版本信息
    if (iph->version != 4)
    {
        printk("Not IPv4.");
        return ret;
    }

    Node tnode = {0, 0, 0, 0, 0, 0, 0, false, false, NULL};

    //获取源、目的IP信息
    tnode.sip = iph->saddr;
    tnode.dip = iph->daddr;

    //char temp[20];
    //printk("sip is %s\n",get_string_ip_addr(tnode.sip,temp,20));

    //获取协议与端口信息
    tnode.protocol = 0; //???无意义语句

    struct tcphdr *tcph; //运输层协议头部声明
    struct udphdr *udph;

    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4)); //iph->ihl为IP报文头部长度，单位为4字节，这里的表达式为TCP头部的地址
        tnode.sport = ntohs(tcph->source);
        tnode.dport = ntohs(tcph->dest);
        tnode.protocol = IPPROTO_TCP;
        break;

    case IPPROTO_UDP:
        udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
        tnode.sport = ntohs(udph->source);
        tnode.dport = ntohs(udph->dest);
        tnode.protocol = IPPROTO_UDP;
        break;

    case IPPROTO_ICMP:
        tnode.protocol = IPPROTO_ICMP;
        tnode.sport = 0;
        tnode.dport = 0;
        break;
    default:
        return ret;
    }

    //对于TCP数据包，只对syn标志位为1的进行防火墙规则匹配,其余的只需要与连接表匹配即可，fin位为1的数据包将在连接表中删除对应的连接
    if (tnode.protocol == IPPROTO_TCP && tcph->syn != 1) //处理syn不为1的TCP数据包
    {
        if (find_link_node(&tnode) || default_rule == NF_ACCEPT) //连接表查询
        {
            ret = NF_ACCEPT;
        }
        else
            ret = NF_DROP;

        if (tcph->fin == 1) //fin为1，连接表删除
        {
            delete_link_node(&tnode);
        }
    }
    else //处理syn为1的TCP数据包以及其他协议的报文
    {
        //尝试查找对应的防火墙规则
        Node *p = find_firewall_node(&tnode);
        //没有对应规则就返回
        if (p == NULL)
        {
            //printk("default action!\n");
            ret = default_rule;
        }
        else
        {
            printk("find a rule\n");

            //判断是否允许该IP报文的通过
            if (!p->isPermit)
            {
                ret = NF_DROP;
                printk("drop!\n");
            }
            else
                ret = NF_ACCEPT; //修改默认策略用到
            //判断是否需要记录日志
            if (p->isLog)
            {
                printk("add_log_node!\n");
                add_log_node(&tnode, p);
            }
        }

        if (tnode.protocol == IPPROTO_TCP && ret == NF_ACCEPT)
        { //通过防火墙规则检查的TCP数据包，成功建立连接，连接表记录该连接
            add_link_node(&tnode);
        }
    }

    return ret;
}

unsigned int hook_func_entry_nat(unsigned int hooknum,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *))
{

    if (!nat_ctl_signal)
        return NF_ACCEPT;
    //printk("hook_func_entry_nat!\n");

    struct iphdr *iph = ip_hdr(skb);

    if (!skb || !iph)
    {
        return NF_ACCEPT;
    }

    if (iph->version != 4)
    {
        return NF_ACCEPT;
    }

    NatNode nnode = {0, 0, 0, 0, NULL};

    nnode.dip = iph->daddr;

    struct tcphdr *tcph;
    struct udphdr *udph;

    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
        nnode.dport = ntohs(tcph->dest);
        break;

    case IPPROTO_UDP:
        udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
        nnode.dport = ntohs(udph->dest);
        break;
    default:
        return NF_ACCEPT;
    }

    //NAT,外网至内网部分，由于需要判断包是否可以通过，所以需要先将IP报文的目的地址由路由器主机的地址变为内网地址，此过程需要查询NAT规则表
    if (nnode.dip == hostIP_out)
    //if (nnode.dip == hostIP)
    {
        printk("DST_NAT START!\n");
        if (!find_dst_nat_node(&nnode))
            return NF_ACCEPT;

        iph->daddr = nnode.sip;

        int tot_len;
        int iph_len;
        iph_len = ip_hdrlen(skb);
        tot_len = ntohs(iph->tot_len);

        switch (iph->protocol)
        {
        case IPPROTO_TCP:
            tcph->dest = htons(nnode.sport);
            tcph->check = 0;
            skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len, 0);
            tcph->check = csum_tcpudp_magic(iph->saddr,
                                            iph->daddr,
                                            ntohs(iph->tot_len) - iph_len, iph->protocol,
                                            skb->csum);
            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);
            break;

        case IPPROTO_UDP:
            udph->dest = htons(nnode.sport);
            iph->check = 0;
            break;
        }
    }
    return NF_ACCEPT;
}

unsigned int hook_func_out_nat(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *))
{

    if (!nat_ctl_signal)
        return NF_ACCEPT;
    //printk("hook_func_out_nat!\n");

    struct iphdr *iph = ip_hdr(skb);

    if (!skb || !iph)
    {
	//printk("1\n");        
	return NF_ACCEPT;
    }

    if (iph->version != 4)
    {
	//printk("2\n");        
	return NF_ACCEPT;
    }
	
    NatNode nnode = {0, 0, 0, 0, NULL};

    nnode.sip = iph->saddr;
    nnode.dip = hostIP_out;
    //nnode.dip = hostIP;    

    struct tcphdr *tcph;
    struct udphdr *udph;

    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
        nnode.sport = ntohs(tcph->source);
        break;

    case IPPROTO_UDP:
        udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
        nnode.sport = ntohs(udph->source);
        break;

    default:
	//printk("3\n");
        return NF_ACCEPT;
    }

    char temp[20];
    printk("sip:%s    %u\n",get_string_ip_addr(nnode.sip,temp,20),nnode.sip);
    //printk("sip:%s    %u\n",get_string_ip_addr(nnode.sip,temp,20),nnode.sip);
    //printk("hostip:%s    %u\n",get_string_ip_addr(hostIP,temp,20),hostIP);
    //printk("netmask:%s    %u\n",get_string_ip_addr(hostnetmask,temp,20),hostnetmask);
    //printk("%u\n",nnode.sip&hostnetmask);
    //printk("%u\n",hostIP&hostnetmask);
    //NAT，内网至外网部分，已经判断是否可以通过，将IP报文的源地址修改为路由器主机的地址，同时增加NAT规则，IP->IP,port->port
    if ((nnode.sip & hostnetmask) == (hostIP & hostnetmask) && hostIP != nnode.sip) //判断报文是否来自内网
    {
        printk("SRC_NAT START!\n");
        iph->saddr = nnode.dip;

        int tot_len;
        int iph_len;
        iph_len = ip_hdrlen(skb);
        tot_len = ntohs(iph->tot_len);

        switch (iph->protocol)
        {
        case IPPROTO_TCP:
            if (find_src_nat_node(&nnode))
            {
                tcph->source = htons(nnode.dport);
            }
            else
            {
                nnode.dport = disport;
                disport++;
                tcph->source = htons(nnode.dport);
                add_nat_node(&nnode);
            }
            tcph->check = 0;
            skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len, 0);
            tcph->check = csum_tcpudp_magic(iph->saddr,
                                            iph->daddr,
                                            ntohs(iph->tot_len) - iph_len, iph->protocol,
                                            skb->csum);
            iph->check = 0;
            iph->check = ip_fast_csum(iph, iph->ihl);
            break;

        case IPPROTO_UDP:
            if (find_src_nat_node(&nnode))
            {
                udph->source = htons(nnode.dport);
            }
            else
            {
                nnode.dport = disport;
                disport++;
                udph->source = htons(nnode.dport);
                add_nat_node(&nnode);
            }
            iph->check = 0;
            break;
        }
    }
    return NF_ACCEPT;
}

/*规则链表操作*/
/*增加*/
void add_firewall_node(Node *newnode)
{
    Node *t;
    t = (Node *)kmalloc(sizeof(Node), 0);
    memcpy(t, newnode, sizeof(struct Node));
    t->next = NULL;

    if (lheader->next == NULL)
    {
        lheader->next = t;
        ltail = t;
    }
    else
    {
        ltail->next = t;
        ltail = t;
    }
}

void add_nat_node(NatNode *newnode)
{
    NatNode *t;
    t = (NatNode *)kmalloc(sizeof(NatNode), 0);
    memcpy(t, newnode, sizeof(struct NatNode));
    t->next = NULL;

    if (nheader->next == NULL)
    {
        nheader->next = t;
        ntail = t;
    }
    else
    {
        ntail->next = t;
        ntail = t;
    }
    nheader->dip++;
}

void add_link_node(Node *tnode)
{
    if (find_link_node(tnode))
        return;
    LinkNode *t;
    t = (LinkNode *)kmalloc(sizeof(LinkNode), 0);
    t->sip = tnode->sip;
    t->sport = tnode->sport;
    t->dip = tnode->dip;
    t->dport = tnode->dport;
    struct timeval timer;
    do_gettimeofday(&timer);
    t->start = timer.tv_sec;
    t->lifetime = 60;
    t->next = NULL;

    if (kheader->next == NULL)
    {
        kheader->next = t;
        ktail = t;
    }
    else
    {
        ktail->next = t;
        ktail = t;
    }
    kheader->dip++;
}

void add_log_node(Node *packageNode, Node *ruleNode)
{
    if (gheader->dip >= 500)
        return;
    //printk("add_log_node--------1--------\n");
    LogNode *t = (LogNode *)kmalloc(sizeof(LogNode), 0);

    //printk("add_log_node--------2--------\n");
    /*时间*/
    struct timex txc;
    struct rtc_time tm;
    do_gettimeofday(&(txc.time));
    rtc_time_to_tm(txc.time.tv_sec, &tm);
    //printk("add_log_node--------3--------\n");

    t->year = tm.tm_year + 1900;
    t->month = (tm.tm_mon) % 12 + 1;
    t->day = tm.tm_mday;
    t->hour = (tm.tm_hour + 8) % 24;
    t->minute = tm.tm_min;
    t->second = tm.tm_sec;

    //printk("add_log_node--------4--------\n");
    t->sip = packageNode->sip;
    t->dip = packageNode->dip;
    t->sport = packageNode->sport;
    t->dport = packageNode->dport;
    t->protocol = packageNode->protocol;

    //printk("add_log_node--------5--------\n");
    t->rule_sip = ruleNode->sip;
    t->rule_dip = ruleNode->dip;
    t->rule_sport = ruleNode->sport;
    t->rule_dport = ruleNode->dport;
    t->rule_protocol = ruleNode->protocol;
    t->rule_permit = ruleNode->isPermit;

    t->next = NULL;

    //printk("add_log_node--------6--------\n");

    gtail->next = t;
    gtail = t;

    gheader->dip++;
    //printk("add_log_node--------7--------\n");
    return;
}
/*删除*/
void delete_firewall_node(Node *tnode)
{
    //空链表直接return
    if (lheader->next == NULL)
    {
        return;
    }

    Node *p = lheader;
    Node *pre = p;
    bool finded = false;
    while (p && p->next != NULL)
    {
        pre = p;
        p = p->next;

        //对比9个参数，任意一个不相等，则继续下一个循环
        if (p->sip != tnode->sip || p->dip != tnode->dip)
        {
            continue;
        }

        if (p->sport != tnode->sport || p->dport != tnode->dport)
        {
            continue;
        }

        if (p->protocol != tnode->protocol)
        {
            continue;
        }

        if (p->sMask != tnode->sMask || p->dMask != tnode->dMask)
        {
            continue;
        }

        if (p->isLog != tnode->isLog || p->isPermit != tnode->isPermit)
        {
            continue;
        }

        //打印该节点信息
        //printk("delete notice: sip:%d,dip:%d,sport:%d,dport:%d,protocol:%d",p->sip,p->dip,p->sport,p->dport,p->protocol);
        //printk("sMask:%d,dMask:%d,isPermit:%s,isLog:%s\n",p->sMask,p->dMask,p->isPermit ? "true" : false,p->isLog ? "true" : "false");
        finded = true;
        break;
    }

    if (!finded)
    {
        return;
    }

    if (ltail == p)
    { //是最后一个
        ltail = pre;
        pre->next = NULL;
    }
    else
    { //其他
        pre->next = p->next;
    }

    kfree(p);
}

void delete_link_node(Node *tnode)
{
    if (kheader->next == NULL && ktail == NULL)
    {
        return;
    }

    LinkNode *p = kheader;
    LinkNode *pre = p;
    bool finded = false;
    while (p && p->next != NULL)
    {
        pre = p;
        p = p->next;

        //对比4个参数，任意一个不相等，则继续下一个循环
        if (p->sip != tnode->sip || p->dip != tnode->dip)
        {
            continue;
        }

        if (p->sport != tnode->sport || p->dport != tnode->dport)
        {
            continue;
        }

        //打印该节点信息
        //printk("link delete notice: sip:%d,dip:%d,sport:%d,dport:%d\n",p->sip,p->dip,p->sport,p->dport);
        finded = true;
        break;
    }

    if (!finded)
    {
        return;
    }
    if (ktail == p)
    { //是最后一个
        ktail = pre;
        pre->next = NULL;
    }
    else
    { //其他
        pre->next = p->next;
    }

    kfree(p);
    kheader->dip--;
}

/*清空*/
void clear_firewall_node(void)
{
    Node *p = lheader->next;
    Node *t = NULL;
    while (p != NULL)
    {
        t = p->next;
        kfree(p);
        p = t;
    }
    lheader->next = NULL;
    ltail = lheader;
}

void clear_log_node(void)
{
    //printk("in clear func!\n");
    gheader->dip = 0;
    LogNode *p = gheader->next;
    LogNode *t = NULL;
    int cnt = 0;
    while (p != NULL)
    {
        //printk("clear No.cnt gg!\n",cnt++);
        t = p->next;
        kfree(p);
        p = t;
    }
    gheader->next = NULL;
    gtail = gheader;
    //printk("leave clear func!\n");
}

void clear_nat_node(void)
{
    nheader->dip = 0;
    disport = 18000;
    NatNode *p = nheader->next;
    NatNode *t = NULL;

    while (p != NULL)
    {
        t = p->next;
        kfree(p);
        p = t;
    }

    nheader->next = NULL;
    ntail = nheader;
}

/*匹配规则*/
Node *find_firewall_node(Node *tnode)
{

    Node *p = lheader;
    //规则节点信息
    unsigned int sip, dip;
    unsigned short sport, dport;
    unsigned short smask, dmask;

    //待查信息
    unsigned int tsip = tnode->sip, tdip = tnode->dip;
    unsigned short tsport = tnode->sport, tdport = tnode->dport;
    unsigned short tprotocol = tnode->protocol;

    //int counter = -1;
    //bool finded = false;
    unsigned int t1 = 0, t2 = 0;

    //找到一个可以匹配的规则，且其处理方式是丢弃
    while (p->next != NULL)
    {

        p = p->next;
        //counter++;
        //finded = false;

        sip = p->sip;
        dip = p->dip;
        smask = p->sMask;
        dmask = p->dMask;
        sport = p->sport;
        dport = p->dport;

        t1 = (sip >> (32 - smask)) << (32 - smask);
        t2 = (tsip >> (32 - smask)) << (32 - smask);
        if (tsip != sip && sip != 0 && (smask <= 0 || (smask > 0 && (t2 & t1) != t1)))
        { //不相等或规则不是any或掩码不同
            continue;
        }

        t1 = (dip >> (32 - dmask)) << (32 - dmask);
        t2 = (tdip >> (32 - dmask)) << (32 - dmask);
        if (tdip != dip && dip != 0 && (dmask <= 0 || (dmask > 0 && (t2 & t1) != t1)))
        {
            continue;
        }

        if (tprotocol != p->protocol && p->protocol != 0)
        {
            continue;
        }

        //如果是ICMP、不需要查端口
        if (tprotocol == IPPROTO_ICMP)
        {
            //finded = true;
            //break;
            return p;
        }

        if (tsport != sport && sport != 0)
        {
            continue;
        }

        if (tdport != dport && dport != 0)
        {
            continue;
        }

        return p;
        //finded = true;
        //break;
    }

    return NULL;
    //return finded ? counter : -1;
}

bool find_dst_nat_node(NatNode *nnode)
{
    NatNode *p = nheader->next;
    while (p != NULL)
    {
        if (p->dport == nnode->dport)
        {
            nnode->sport = p->sport;
            nnode->sip = p->sip;
            return true;
        }
        p = p->next;
    }
    return false;
}

bool find_src_nat_node(NatNode *nnode)
{
    NatNode *p = nheader->next;
    while (p != NULL)
    {
        if (p->sip == nnode->sip && p->sport == nnode->sport)
        {
            nnode->dip = p->dip;
            nnode->dport = p->dport;
            return true;
        }
        p = p->next;
    }
    return false;
}

int find_link_node(Node *tnode)
{
    LinkNode *p = kheader;
    struct timeval timer;
    while (p->next != NULL)
    {
        p = p->next;
        if (p->sip == tnode->sip && p->sport == tnode->sport && p->dip == tnode->dip && p->dport == tnode->dport)
        {
            do_gettimeofday(&timer);
            p->start = timer.tv_sec;
            p->lifetime = 60;
            return 1;
        }
    }
    return 0;
}

//初始化链表
void init_all_list(void)
{
    lheader = (Node *)kmalloc(sizeof(Node), 0); //申请头结点空间
    lheader->next = NULL;
    ltail = lheader;

    nheader = (NatNode *)kmalloc(sizeof(NatNode), 0);
    nheader->dip = 0;
    nheader->next = NULL;
    ntail = nheader;

    kheader = (LinkNode *)kmalloc(sizeof(LinkNode), 0);
    kheader->dip = 0; //
    kheader->next = NULL;
    ktail = kheader;

    gheader = (LogNode *)kmalloc(sizeof(LogNode), 0);
    gheader->dip = 0; //
    gheader->next = NULL;
    gtail = gheader;
}

void time_func(unsigned long arg)
{
    struct timeval tv;
    do_gettimeofday(&tv);

    LinkNode *p = kheader;
    LinkNode *pre = p;
    while (p != NULL && p->next != NULL)
    {
        pre = p;
        p = p->next;
        if (p->lifetime <= 0)
        {
            if (ktail == p)
            { //是最后一个
                ktail = pre;
                pre->next = NULL;
            }
            else
            { //其他
                pre->next = p->next;
            }
            kfree(p);
            kheader->dip--;
            p = pre;
        }
    }
    p = kheader;
    while (p->next != NULL)
    {
        p = p->next;
        p->lifetime--;
    }

    oldtv = tv;
    tm.expires = jiffies + 1 * HZ;
    add_timer(&tm); //重新开始计时
}
/*字符设备初始化*/
static int __init my_netfilter_init(void)
{
    int ret;
    dev_t devno;
    if (major_number)
    {
        devno = MKDEV(major_number, minor_number);
        ret = register_chrdev_region(devno, 1, CDEV_NAME);
    }
    else
    {
        ret = alloc_chrdev_region(&devno, major_number, 1, CDEV_NAME);
        major_number = MAJOR(devno);
    }
    if (ret < 0)
    {
        return ret;
    }
    cdev_init(&netfilter_cdev, &netfilter_cdev_fops); //字符设备静态内存定义初始化
    cdev_add(&netfilter_cdev, devno, 1);              //传入 cdev 结构的指针，起始设备编号，以及设备编号范围。

    class = class_create(THIS_MODULE, CLASS_NAME);
    device = device_create(class, NULL, devno, NULL, CLASS_NAME);
    //注册hook
    nf_register_hook(&hook_options_entry_nat);
    nf_register_hook(&hook_options_entry_firewall);
    nf_register_hook(&hook_options_out_firewall);
    nf_register_hook(&hook_options_out_nat);

    //初始化规则链表
    init_all_list();

    //定时器相关
    init_timer(&tm); //初始化内核定时器

    do_gettimeofday(&oldtv);       //获取当前时间
    tm.function = time_func;       //指定定时时间到后的回调函数
    tm.expires = jiffies + 1 * HZ; //定时时间
    add_timer(&tm);                //注册定时器

    printk("Register successful!\nMain Device Number is %d\n", major_number);
    return 0;
}

/*字符设备释放*/
static void __exit my_netfilter_exit(void)
{
    dev_t devno = MKDEV(major_number, minor_number);
    device_destroy(class, devno);
    class_unregister(class);
    class_destroy(class);
    nf_unregister_hook(&hook_options_entry_nat);
    nf_unregister_hook(&hook_options_entry_firewall);
    nf_unregister_hook(&hook_options_out_firewall);
    nf_unregister_hook(&hook_options_out_nat);
    del_timer(&tm); //注销定时器
    cdev_del(&netfilter_cdev);
    unregister_chrdev_region(MKDEV(major_number, 0), 1);
    printk("Exit!\n");
}

/*各类数字字符串转化函数*/
unsigned int get_uint_ip_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a;
    arr[1] = b;
    arr[2] = c;
    arr[3] = d;
    return *(unsigned int *)arr;
}

char *get_string_ip_addr(unsigned int ip, char *sp, unsigned int len)
{
    char buf[len];
    unsigned t = 0x000000ff;

    if (ip == 0)
    { // ANY
        sprintf(buf, "%s", "ANY");
    }
    else
    {
        sprintf(buf, "%d.%d.%d.%d", ip & t, (ip >> 8) & t, (ip >> 16) & t, (ip >> 24) & t);
    }
    strncpy(sp, buf, len);
    return sp;
}

char *getPortString(unsigned short port, char *sp, unsigned short len)
{
    char buf[len];

    if (port == 0)
    {
        sprintf(buf, "%s", "ANY");
    }
    else
    {
        sprintf(buf, "%d", port);
    }

    strncpy(sp, buf, len);
    return sp;
}

char *getProtocolString(unsigned int protocol, char *sp, unsigned short len)
{
    switch (protocol)
    {
    case IPPROTO_TCP:
        strncpy(sp, "IPPROTO_TCP", len);
        break;
    case IPPROTO_UDP:
        strncpy(sp, "IPPROTO_UDP", len);
        break;
    case IPPROTO_ICMP:
        strncpy(sp, "IPPROTO_ICMP", len);
        break;
    }
    return sp;
}

module_init(my_netfilter_init); // insmod module
module_exit(my_netfilter_exit); // rmmod module
