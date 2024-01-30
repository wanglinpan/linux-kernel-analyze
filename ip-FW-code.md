# IP协议源码分析
one TCP/IP start:

(1.) ip6_session_core_in -->resolve_ip6_tuple-->resolve_ip6_tuple_fast

(2.)fw6_pre_route_handler-->iprope6_dnat_check-->iprope6_policy_group_dnat_check-->__iprope6_dnat_check-->get_new_addr6

(3.) iprope6_access_proxy_check-->iprope6_policy_group_check-->__iprope6_check-->iprope6_check_one_policy

（4.）iprope6_fwd_check
      iprope6_policy_tree_check
      __iprope6_tree_check
      iprope6_check_one_policy-->do6_fwd_check

（5.）fw6_local_in_handler -->iprope6_in_check
   iprope6_policy_group_check-->__iprope6_check -->do6_fwd_check (IPROPE_GRP_IN :0x100001)
   iprope6_policy_group_check-->__iprope6_check-->do6_fwd_check (IPROPE_GRP_IMPLICIT_IN :0x10000E)
   iprope6_policy_group_check-->__iprope6_check-->do6_fwd_check (IPROPE_GRP_ADMIN_IN :0x10000F)

## Kernel gum  --> user config
all 
linux-3.2.16/include/linux/iprope.h

IPROPE_GRP_IN -->> config fireware local-in-policy
IPROPE_GRP_IMPLICIT_IN-->iprope6_set_in_by_cmdbsvr set lots default value

IPROPE_GRP_ADMIN_IN -->iprope6_set_admin_access

：

```c
struct iphdr {
    __u8    version:4,
            ihl:4;
    __u8    tos;
    __u16   tot_len;
    __u16   id;
    __u16   frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __u32   saddr;
    __u32   daddr;
    /*The options start here. */
};
```

`IP头部` 结构的各个字段与上图的所展示的字段是一一对应的。

虽然 `IP头部` 看起来好像很复杂，但如果按每个字段所支持的功能来分析，就会豁然开朗。一个被添加上 `IP头部` 的数据包如下图所示：

![ip-package](https://raw.githubusercontent.com/liexusong/linux-source-code-analyze/master/images/ip-package.png)

当然，除了 `IP头部` 外，在一个网络数据包中还可能包含一些其他协议的头部，比如 `TCP头部`，`以太网头部` 等，但由于这里只分析 `IP协议`，所以只标出了 `IP头部`。

接下来，我们通过源码来分析 Linux 内核是怎么实现 `IP协议` 的，我们主要分析 IP 数据包的发送与接收过程。

## IP数据包的发送

要发送一个 IP 数据包，可以通过两个接口来完成：`ip_queue_xmit()` 和 `ip_build_xmit()`。第一个主要用于 TCP 协议，而第二个主要用于 UDP 协议。

我们主要分析 `ip_queue_xmit()` 这个接口，`ip_queue_xmit()` 代码如下：

```c
int ip_queue_xmit(struct sk_buff *skb)
{
    struct sock *sk = skb->sk;
    struct ip_options *opt = sk->protinfo.af_inet.opt;
    struct rtable *rt;
    struct iphdr *iph;

    rt = (struct rtable *)__sk_dst_check(sk, 0); // 是否有路由信息缓存
    if (rt == NULL) {
        u32 daddr;
        u32 tos = RT_TOS(sk->protinfo.af_inet.tos)|RTO_CONN|sk->localroute;

        daddr = sk->daddr;
        if(opt && opt->srr)
            daddr = opt->faddr;

        // 通过目标IP地址获取路由信息
        if (ip_route_output(&rt, daddr, sk->saddr, tos, sk->bound_dev_if))
            goto no_route;
        __sk_dst_set(sk, &rt->u.dst); // 设置路由信息缓存
    }

    skb->dst = dst_clone(&rt->u.dst); // 绑定数据包的路由信息
    ...
    // 获取数据包的IP头部指针
    iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr)+(opt?opt->optlen:0));

    // 设置 版本 + 头部长度 + 服务类型
    *((__u16 *)iph) = htons((4<<12)|(5<<8)|(sk->protinfo.af_inet.tos & 0xff));

    iph->tot_len  = htons(skb->len);           // 设置总长度
    iph->frag_off = 0;                         // 分片偏移量
    iph->ttl      = sk->protinfo.af_inet.ttl;  // 生命周期
    iph->protocol = sk->protocol;              // 上层协议(如TCP或者UDP等)
    iph->saddr    = rt->rt_src;                // 源IP地址
    iph->daddr    = rt->rt_dst;                // 目标IP地址

    skb->nh.iph = iph;
    ...
    // 调用 ip_queue_xmit2() 进行下一步的发送操作
    return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
                   ip_queue_xmit2);
}
```

`ip_queue_xmit()` 函数的参数是要发送的数据包，其类型为 `sk_buff`。在内核协议栈中，所有要发送的数据都是通过 `sk_buff` 结构来作为载体的。`ip_queue_xmit()` 函数主要完成以下几个工作：

*   首先调用 `__sk_dst_check()` 函数获取路由信息缓存，如果路由信息还没被缓存，那么以 `目标IP地址` 作为参数调用 `ip_route_output()` 函数来获取路由信息，并且设置路由信息缓存。路由信息一般包含发送数据的设备对象（网卡设备）和下一跳路由的 `IP地址`。
*   绑定数据包的路由信息。
*   获取数据包的 `IP头部` 指针，然后设置 `IP头部` 的各个字段的值，如代码注释所示，可以对照 `IP头部` 结构图来分析。
*   调用 `ip_queue_xmit2()` 进行下一步的发送操作。

我们接着分析 `ip_queue_xmit2()` 函数的实现，代码如下：

```c
static inline int ip_queue_xmit2(struct sk_buff *skb)
{
    struct sock *sk = skb->sk;
    struct rtable *rt = (struct rtable *)skb->dst;
    struct net_device *dev;
    struct iphdr *iph = skb->nh.iph;
    ...
    // 如果数据包的长度大于设备的最大传输单元, 那么进行分片操作
    if (skb->len > rt->u.dst.pmtu)
        goto fragment;

    if (ip_dont_fragment(sk, &rt->u.dst))         // 如果数据包不能分片
        iph->frag_off |= __constant_htons(IP_DF); // 设置 DF 标志位为1

    ip_select_ident(iph, &rt->u.dst); // 设置IP数据包的ID(标识符)

    // 计算 IP头部 的校验和
    ip_send_check(iph);

    skb->priority = sk->priority;
    return skb->dst->output(skb); // 把数据发送出去(一般为 dev_queue_xmit)

fragment:
    ...
    ip_select_ident(iph, &rt->u.dst);
    return ip_fragment(skb, skb->dst->output); // 进行分片操作
}
```

`ip_queue_xmit2()` 函数主要完成以下几个工作：

*   判断数据包的长度是否大于最大传输单元（`最大传输单元 Maximum Transmission Unit，MTU` 是指在传输数据过程中允许报文的最大长度），如果大于最大传输单元，那么就调用 `ip_fragment()` 函数对数据包进行分片操作。
*   如果数据包不能进行分片操作，那么设置 `DF（Don't Fragment）` 位为 1。
*   设置 IP 数据包的 ID（标识符）。
*   计算 `IP头部` 的校验和。
*   通过网卡设备把数据包发送出去，一般通过调用 `dev_queue_xmit()` 函数。

`ip_queue_xmit2()` 函数会继续设置 `IP头部` 其他字段的值，然后调用 `dev_queue_xmit()` 函数把数据包发送出去。

当然还要判断发送的数据包长度是否大于最大传输单元，如果大于最大传输单元，那么就需要对数据包进行分片操作。数据分片是指把要发送的数据包分割成多个以最大传输单元为最大长度的数据包，然后再把这些数据包发送出去。

## IP数据包的接收

IP数据包的接收是通过 `ip_rcv()` 函数完成的，当网卡接收到数据包后，会上送到内核协议栈的链路层，链路层会根据链路层协议（如以太网协议）解析数据包。然后再将解析后的数据包通过调用 `ip_rcv()` 函数上送到网络层的 `IP协议`，`ip_rcv()` 函数的实现如下：

```c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
{
    struct iphdr *iph = skb->nh.iph; // 获取数据包的IP头部

    if (skb->pkt_type == PACKET_OTHERHOST) // 如果不是发送给本机的数据包, 则丢掉这个包
        goto drop;
    ...
    // 判断数据包的长度是否合法
    if (skb->len < sizeof(struct iphdr) || skb->len < (iph->ihl<<2))
        goto inhdr_error;

    // 1. 判断头部长度是否合法
    // 2. IP协议的版本是否合法
    // 3. IP头部的校验和是否正确
    if (iph->ihl < 5 || iph->version != 4 || ip_fast_csum((u8 *)iph, iph->ihl) != 0)
        goto inhdr_error;

    {
        __u32 len = ntohs(iph->tot_len);
        if (skb->len < len || len < (iph->ihl<<2)) // 数据包的长度是否合法
            goto inhdr_error;

        __skb_trim(skb, len);
    }

    // 继续调用 ip_rcv_finish() 函数处理数据包
    return NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, dev, NULL, ip_rcv_finish);

inhdr_error:
    IP_INC_STATS_BH(IpInHdrErrors);
drop:
    kfree_skb(skb);
out:
    return NET_RX_DROP;
}
```

`ip_rcv()` 函数的主要工作就是验证 `IP头部` 各个字段的值是否合法，如果不合法就将数据包丢弃，否则就调用 `ip_rcv_finish()` 函数继续处理数据包。



`ip_rcv_finish()` 函数的实现如下：

```c
static inline int ip_rcv_finish(struct sk_buff *skb)
{
    struct net_device *dev = skb->dev;
    struct iphdr *iph = skb->nh.iph;

    // 根据源IP地址、目标IP地址和服务类型查找路由信息
    if (skb->dst == NULL) {
        if (ip_route_input(skb, iph->daddr, iph->saddr, iph->tos, dev))
            goto drop;
    }
    ...

    // 如果是发送给本机的数据包将会调用 ip_local_deliver() 处理
    return skb->dst->input(skb);
}
```

`ip_rcv_finish()` 函数的实现比较简单，首先以 `源IP地址`、`目标IP地址` 和 `服务类型` 作为参数调用 `ip_route_input()` 函数查找对应的路由信息。

然后通过调用路由信息的 `input()` 方法处理数据包，如果是发送给本机的数据包 `input()` 方法将会指向 `ip_local_deliver()` 函数。



我们接着分析 `ip_local_deliver()` 函数：

```c
int ip_local_deliver(struct sk_buff *skb)
{
    struct iphdr *iph = skb->nh.iph;

    // 如果是一个IP数据包的分片
    if (iph->frag_off & htons(IP_MF|IP_OFFSET)) {
        skb = ip_defrag(skb); // 将分片组装成真正的数据包，如果成功将会返回组装后的数据包
        if (!skb)
            return 0;
    }

    // 继续调用 ip_local_deliver_finish() 函数处理数据包
    return NF_HOOK(PF_INET, NF_IP_LOCAL_IN, skb, skb->dev, NULL,
                   ip_local_deliver_finish);
}
```

`ip_local_deliver()` 函数首先判断数据包是否是一个分片，如果是分片的话，就调用 `ip_defrag()` 函数对分片进行重组操作。重组成功的话，会返回重组后的数据包。接着调用 `ip_local_deliver_finish()` 对数据包进行处理。



`ip_local_deliver_finish()` 函数的实现如下：

```c
static inline int ip_local_deliver_finish(struct sk_buff *skb)
{
    struct iphdr *iph = skb->nh.iph;

    skb->h.raw = skb->nh.raw + iph->ihl*4; // 设置传输层头部(如TCP/UDP头部)

    {
        int hash = iph->protocol & (MAX_INET_PROTOS - 1); // 传输层协议对应的hash值
        struct sock *raw_sk = raw_v4_htable[hash];
        struct inet_protocol *ipprot;
        int flag;
        ...

        // 通过hash值找到传输层协议的处理函数
        ipprot = (struct inet_protocol *)inet_protos[hash]; 
        flag = 0;

        if (ipprot != NULL) {
            if (raw_sk == NULL 
                && ipprot->next == NULL 
                && ipprot->protocol == iph->protocol) 
            {
                // 调用传输层的数据包处理函数处理数据包
                return ipprot->handler(skb, (ntohs(iph->tot_len) - iph->ihl*4));
            } else {
                flag = ip_run_ipprot(skb, iph, ipprot, (raw_sk != NULL));
            }
        }
        ...
    }
    return 0;
}
```

`ip_local_deliver_finish()` 函数的主要工作就是根据上层协议（传输层）的类型，然后从 `inet_protos` 数组中找到其对应的数据包处理函数，然后通过此数据包处理函数处理数据。

也就是说，IP层对数据包的正确性验证完成和重组后，会将数据包上送给传输层去处理。对于 `TCP协议` 来说，数据包处理函数对应的是 `tcp_v4_rcv()`。

