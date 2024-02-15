# IP Session  关键结构和接口
linux-3.2.16/include/linux/netfilter_ipv4/ip_session.h
```c
struct ip_session{
    /*-------- FREQUENTLY USED -----------------*/
    atomic_t ses_refcnt;
    u32 last_ses_Bps_jiffies;
    struct ip_tuple   tuple[IP_SESSION_MAX_TUPLE];

    union {
	struct timer_list   timer; // timeout value of the session
	struct rcu_head rcu;
    };
    rwlock_t lock;
    u32 timeout;
    u32 dead;
    volatile u32 state_ext;
    u16 vf;
    u8 ses_vrf;
    __u32 state; // REDIRECT, NEW_SESSION,LOG, IDS_BLOCK
    __u32 state2;
    unsigned int generation;
    __u8 proto; // protocol of session
    __u8 ha_id;
    __u8 tuple_num; // number of tuple used

    u8 term_report:1, nat_af:2, wccp_router_mode:1, anti_replay_disabled:1,
	ips_src_inc:1, ips_dst_inc:1, ips_ip_src_inc:1, ips_ip_dst_inc:1;
    u8 tcp_sctp_no_start: 1; // TCP session without syn, or SCTP session without init.
    u8 tcp_challenge_ack:1;
    u8 ips_sess_notif:1;
    u8 ips_ngfw_pol_deny:1;  // security policy act for log only, IPS can send blockpage
    u8 refresh_dir_mask:2;
    void *dst[2];
    /* do not add new field in above area */

    struct ip_session *accounting_ses;
    struct policy_statistic_meter *pol_stats; 
    struct session_stat s[2];
    struct ip_session __rcu *master; // master session creating this session, ftp etc.
    struct tr_stat_element *tr_stat;
    ip_session_proto_func proto_func;
    u32 (* get_timeout)(struct ip_session * ses);
    struct ip_session_help_ops  *helper; // for FTP,IRC, to create slave session.,change data

    unsigned long last_acc, last_used;
#ifdef CONFIG_FORTICONTROLLER_ASSISTANT
    unsigned long last_assist_tx;
#endif
#define IP_SESSION_SK_PROTO_STATE		0
#define IP_SESSION_SK_EPH			1
#define IP_SESSION_SK_ESTABLISHED		2
    volatile long unsigned int state_keeper;

    int  indev[2]; // incomming dev when session create
    int  outdev[2]; //outgoing dev when packet route

    unsigned int tcp_halfclose_ttl;
    unsigned int tcp_halfopen_ttl;
    u16 tcp_timewait_ttl;
    u16 tcp_rst_ttl;

    unsigned short vwp_vlanid;
    unsigned short tcp_mss[2];
    unsigned char tos[2]; // diffserv for forward and reverse (-1 = no-change)
    unsigned char log_tos[2]; // original ToS for forward and reverse
    u8 vlan_cos[2];
    unsigned char tcp_close_state[2]; // tcp close state
    __u8 proto_state[2]; // TCP state
    __u8 tcp_ack_state[2]; // TCP ack state 
    __u8 orgin_hook[2], sink_hook[2]; //where the session created and terminated.

    /* min_acc means some entities wish this session to live at least a period
     * of time.
     * It will be set to zero after jiffies passes that period of time.
     */
    u8 min_acc:1;
    u8 keep_ses_alive:1;
    u8 ips_scan_inc:1;
    u8 fw_reflect_master:1;
    u8 snat:1;
    u8 fixport:1;
    u8 master_detach:1; /* This session originally is en expectation and detached from master already. */

    /*
     * Session's dir according to the policy.
     * 0: same as policy;
     * 1: reverse of policy.
     */
    u8 policy_dir_rev:1; 

#define FTP_MODE_DEFAULT 0
#define FTP_MODE_PASV 1
#define FTP_MODE_EPSV 2
#define FTP_MODE_PORT 3
#define FTP_MODE_EPRT 4
    u8 ftp_mode:3;

    /*-------- NOT FREQUENTLY USED -----------------*/
    __u8 master_dir; // the master session direction this session should follow
    __u8 av_idx;
    //PRE_ROUTE_CREATE/LOCAL_OUT_CREATE etc
#define IP_SES_DST_ERR_MAX	5
    __u8 dst_err[2];
    __u8 to_block; //the number of packet could pass before advance into block
    __u8 pkts_block;
    unsigned char check_reset_range;
    u8 url_cat_id;
    u8 class_id;

    u8 src_reputation, dst_reputation;

    u16 service; // dport of original session, used for logging
    __u16 app_list_id;
    u16 sockport;
    u16 socktype;

    unsigned int proxy_flags;
    unsigned int misc;
    unsigned int auth_info;
    unsigned int chk_client_info; // info for checking FortiClient
    unsigned int src_id;
    unsigned int dst_id;
    u32 rpdb_link_id;
    u32 rpdb_svc_id;
    u32 idx; //forward policy index
    u32 c_idx; // central nat index
    u32 shaping_policy_uuid_idx;
    u32 serial; // serial number
    u32 dos;
    __u32 app_id;
    __u32 ngfw_id;
    u32 vendor_id;

    unsigned short naf_sport, naf_dport;
    unsigned long last_sample;
    unsigned long last_log;
    unsigned int src_uuid_idx, dst_uuid_idx, pol_uuid_idx, svc_uuid_idx;
    struct in6_addr naf_saddr, naf_daddr;

    unsigned long hard_life;
    unsigned long jiffies; //ha use

#define OFFLOAD_SES_BPS_UPDATE_INTERVAL 60*HZ
    u64 last_ses_Bps_bytes[2];
    u64 last_ses_Bps[2];

    union{
    	struct ip_session_nat_seq tcp_seq[2]; // for ORG,RELPY 
    	struct icmp_map icmp;
    }un;
	union ip_session_help_u help;
	struct ip_session_exp_s exp;
    struct ip_session __rcu *slave; // all the slave session, FTP data
    struct ip_session __rcu *sibling; // all sister
    void *helper_data;
    void (*trace_back)(struct sk_buff *skb, int hooknum, int dir);

    struct list_head  ephemeral_list;
    struct list_head  expect_list;
    struct list_head ha_link;
    void (*dtor)(struct ip_session * ses);
    void (*ses_release)(struct ip_session * ses);
    struct ip_session *ses_reflect_next;
    struct ip_user *user;
    struct ip_user *dst_user;
    struct mac_host *src_host;
    struct mac_host *dst_host;
    void *local_dst;
    unsigned int tun_id[2];
    struct ipsec_tunnel_common *ips_tun[2];
    struct ip_session_shaper __rcu *shapers[2];
    struct per_ip_quota __rcu *per_ip;
#ifdef CONFIG_CARRIER
    struct gtp_inspect_profile __rcu *gtp;
    struct pfcp_inspect_profile *pfcp;
#endif /* CONFIG_CARRIER */
    struct dme_entry_stats *dms;
    struct wccp_deliver_info *wccp;
    struct ippool_pba_entry *nat_pba;
    struct app_stats __rcu *app_stats;

    struct npu_ips npuips;
    struct nf_conntrack *ips_proxyid[2];
#endif
    struct l2_ext_headers *ext_headers;

    union {
	struct tcp_session_ctx ctx[0];
	struct sctp_session_ctx sctp_ctx[0];
    };
};
```


`ip_local_deliver_finish()` 函数的主要工作就是根据上层协议（传输层）的类型，然后从 `inet_protos` 数组中找到其对应的数据包处理函数，然后通过此数据包处理函数处理数据。

也就是说，IP层对数据包的正确性验证完成和重组后，会将数据包上送给传输层去处理。对于 `TCP协议` 来说，数据包处理函数对应的是 `tcp_v4_rcv()`。

