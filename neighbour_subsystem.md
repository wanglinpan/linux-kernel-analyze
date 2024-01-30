# 邻接子系统的核心用途
  （1.）ARP/NDISC 重要用途避免地址重复。
  （2.）Linux邻接子系统负责发现当前链路上的结点，并且将L3（网络层）地址转换为L2（数
据链路层）地址。在IPv4当中，实现这种转换的协议为地址解析协议（Address Resolution
Protocol，ARP），而在IPv6则为邻居发现协议（Neighbour Discovery Protocol，NDISC
或ND），邻接子系统为执行L3到L2映射提供了独立于协议的基础设施
  （3.） 有时不需要邻接子系统的帮助也能够获悉目标地址。比如发送广播时，在这种情况L2目标地址是固定的，例如，在以太网中为FF：FF：FF：FF：FF：FF，有时目标地址是组播地址，L3组播地址和L2组播地址的映射关系是固定的。
   (4.) 在IPv4中，使用邻接协议为ARP，相应的请求和应答分别被称为ARP请求和ARP应答，
在IPv6中，使用的邻接协议为NDISC，相应的请求和应答分别称为邻居请求和邻居通告。

# 邻接子系统的neighbour的重要结构体定义：
     /include/net/neighbour.h
```c
struct neighbour {
	struct neighbour __rcu	*next; //指向散列表的同一个桶中的下一个邻居
	struct neigh_table	*tbl; //与邻居相关的邻接表
	struct neigh_parms	*parms; //与邻居相关联的neigh＿parms对象，由相关邻接表的构造函数对其进行初始化操作
	unsigned long		confirmed; //confirm update time
	unsigned long		updated;
	rwlock_t		lock;
	atomic_t		refcnt;
	struct sk_buff_head	arp_queue; //一个未解析SKB队列。此成员并非ARP/NDISC
	struct timer_list	timer; // 每个neighbour对象都有一个定时器 
	unsigned long		used;
	atomic_t		probes;
	__u8			flags;
	__u8			nud_state;
	__u8			type;
	__u8			dead:1;
	__u8			logged:1;
	seqlock_t		ha_lock; // 对邻居硬件地址（ha）提供访问保护
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))]; //mac address
	struct hh_cache		hh; //L2报头的硬件报头缓存
	int			(*output)(struct neighbour *, struct sk_buff *);
	void			(*update_notify)(struct neighbour *);
	const struct neigh_ops	*ops;
	struct rcu_head		rcu;
	struct net_device	*dev;
	//邻居的IP地址（L3地址），邻接表查找是根据primary＿key进行的，
	//比如IPv4来讲，长度为4字节；对于IPv6来讲，其长度为sizeof（struct in6＿addr）
	u8			primary_key[0];
};

```

(2.) ARP and NDSIC all is neigh_table sample
```c
struct neigh_table {
	// 有些专门指针next：每种协议都会创建自己的neigh＿table实例
	//对于IPV4邻接表（arp＿tb1 AF＿INET）；对于IPv6邻接表（nd＿tb1 AF＿INET6）
	struct neigh_table	*next;
	int			family;
	int			entry_size;//neigh＿alloc（）分配邻居条目时，分配空间为tb1-＞entry＿size＋dev-＞neigh＿priv＿le
	int			key_len; //查找键长度
	//将键（L3地址）映射到特定散列值的散列函数u32
	__u32			(*hash)(const void *pkey,
					const struct net_device *dev,
					__u32 hash_rnd);
	//创建邻居对象时执行因协议而异的初始化
	int			(*constructor)(struct neighbour *);
	//邻居代理而对于NDISC来讲，它则pndisc＿constructor, NO ARP中不予使用?
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	void			(*proxy_redo)(struct sk_buff *skb);
	char			*id;//邻接表的名称 IPv4——>arp_cache IPv6——>ndisc_cacl
	struct neigh_parms	parms;
	/* HACK. gc_* should follow parms without a gap! */
	int			gc_interval;
	//邻接表条目阈值，用作激活同步垃圾收集器的条件，这用于异步垃圾收集处理程序neigh_periodic_work
	int			gc_thresh1;
	int			gc_thresh2;
	int			gc_thresh3;
	unsigned long		last_flush;//最近一次运行方法neigh_forced_gc（）的时间
	struct delayed_work	gc_work; // 异步垃圾收集处理程序
	//主机被配置为ARP代理时，它可能不会立即处理请示，而是过一段时间再处理
	struct timer_list 	proxy_timer;
	struct sk_buff_head	proxy_queue; //skb proxy queue
	atomic_t		entries;
	rwlock_t		lock;
	unsigned long		last_rand;
	struct kmem_cache	*kmem_cachep;
	struct neigh_statistics	__percpu *stats;
	struct neigh_hash_table __rcu *nht;
	struct pneigh_entry	**phash_buckets;
};


```
(3.) 使用邻接子系统的每种L3协议都还注册一个协议处理程序。对于IPv4来讲，ARP数据
包处理程序方法为arp_rcv()

(4.) 每个邻居对象结构neigh_ops中定义一组方法，它包含一个协议簇成员和4个函数指针，
具体内核源码如下
```c
struct neigh_ops {
	int			family; //IPv4-->AF_INET, IPV6-> AF_INET6
	//send neighbour broadcast req
	void			(*solicit)(struct neighbour *, struct sk_buff *);
	//NUD_FAILED, neigh_invalidate() call it 
	void			(*error_report)(struct neighbour *, struct sk_buff *);
	// Get L3 net hop, but no mac address, call it 
	int			(*output)(struct neighbour *, struct sk_buff *);
	int			(*connected_output)(struct neighbour *, struct sk_buff *);
        void                    (*resolve_state)(struct neighbour *);
	void			(*log_neigh)(struct neighbour *);
};
```
## API 
 neigh_create/neigh_release
  在方法_neigh_create()的最后，将dead标志初始化为0,并将邻居对象添加到邻居散列表中，
  方法neigh release 将邻居的引用计数器减1。如果它变成0,调用方法neigh_destroy()将邻居对象释放。
添加/删除邻居条目
添加使用命令(ip neigh add),执行方法static int neigh_add(struct sk buff *skb, struct nlmsghdr *nlh,
       struct netlink ext ack *extack)₀
删除使用命令(ip neigh del),执行方法static int neigh_delete(struct sk buff *skb, struct nlmsghdr *nlh,
        struct netlink ext ack *extack)₀

##ARP协议细节
(1.) ARP head define
```c
struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address ipv4: 0x80	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/
	//ARPOP_REQUEST/ARPOP_REPLY

};
(2.)arp_process 处理具体的细节, ARP send 
   首先调用方法_ipv4_neigh_lookup_noref,在ARP表中查找下一跳IPv4地址。如果没有找到匹配的邻居条目，就调
用方法_neigh_create()来创建一个。
ip_finish_output2_1 -->__ipv4_neigh_lookup_noref
(3.) IPV4 arp_rcv handle rev packet
 arp_rcv-->arp_process
```
(4.) user 如何查询
arp -a /ip neigh show
migbase/osapi/libnetlink.c

##梳理核心代码调用关系

