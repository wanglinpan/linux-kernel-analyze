#内存消耗过多引起ping not  work
(1.) https://mantis.fortinet.com/bug_view_page.php?bug_id=0969303
https://mantis.fortinet.com/bug_view_page.php?bug_id=0952688
config log disk setting
    set status enable  < --disable>
end

#kernel timer issues
https://mantis.fortinet.com/bug_view_page.php?bug_id=0873097

https://mantis.fortinet.com/bug_view_page.php?bug_id=0960643
diag_user_quarantine_add-->user_quarantine_ban_add
linux-4.19.13/include/linux/timer.h
linux-4.19.13/kernel/time/timer.c
```c
// timer base on tick, it's timer class struct 
struct timer_list {
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */
	struct hlist_node	entry;
	unsigned long		expires;// jiffies + tick
	void			(*function)(struct timer_list *); //timer timeout call func
	u32			flags;
    // the higer 10 bits : bucket number,  the lower 18 bits : which cpu 
#ifdef CONFIG_LOCKDEP
	struct lockdep_map	lockdep_map;
#endif
};
// it organize timer object
struct timer_base {
	raw_spinlock_t		lock;
	struct timer_list	*running_timer; //current cpu hand the timer object
        ......
	unsigned long		clk; //current timer object jiffies 
	unsigned long		next_expiry; //current cpu next expiry object timeout
	unsigned int		cpu; //current cpu id
	bool			is_idle; // work on CONFIG_NO_HZ_COMMON
	bool			must_forward_clk; // work on CONFIG_NO_HZ_COMMON
	DECLARE_BITMAP(pending_map, WHEEL_SIZE); // every bucket bits map, set 1 when have timer object in bucket
	struct hlist_head	vectors[WHEEL_SIZE];
} ____cacheline_aligned;
每个CPU都含有一到两个timer_base结构体变量：
if define CONFIG_NO_HZ_COMMON, Then two timer_base object BASE_STD/BASE_DEF
```