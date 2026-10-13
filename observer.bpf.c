// eBPF observer for one egress interface (loaded by controller.py through BCC).
//
//   net:net_dev_queue      packet handed to the qdisc   -> stamp it, count its flow
//   net:net_dev_start_xmit packet leaves the qdisc      -> sojourn = now - stamp
//
// Sojourn time is therefore measured per packet, for whichever qdisc is
// installed (pfifo included), and aggregated in the kernel into 100 ms slots.
// User space only ever reads the slots and the per-flow table.
//
// NAME_LO/HI and MASK_LO/HI (the interface name as two u64s), WINDOW_NS and
// NSLOTS are passed in as -D flags.

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>

struct flow_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 proto;
};

struct flow_val {
    u64 packets;
    u64 bytes;
    u64 last_ns;
};

struct slot {
    u64 epoch;      // which WINDOW_NS interval this slot currently holds
    u64 count;
    u64 sum_ns;
    u64 min_ns;
    u64 max_ns;
};

BPF_TABLE("lru_hash", u64, u64, enq_ts, 16384);                       // skb -> enqueue time
BPF_TABLE("lru_hash", struct flow_key, struct flow_val, flows, 4096); // five-tuple -> counters
BPF_ARRAY(slots, struct slot, NSLOTS);

static __always_inline int on_target(struct sk_buff *skb)
{
    struct net_device *dev = NULL;
    u64 name[2] = {};

    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (!dev)
        return 0;
    bpf_probe_read_kernel(&name, sizeof(name), &dev->name);
    return (name[0] & MASK_LO) == NAME_LO && (name[1] & MASK_HI) == NAME_HI;
}

static __always_inline void count_flow(struct sk_buff *skb, u32 len, u64 now)
{
    unsigned char *head = NULL;
    u16 nh_off = 0, proto = 0;
    struct iphdr ip = {};
    struct flow_key key = {};
    struct flow_val zero = {}, *val;

    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != htons(ETH_P_IP))
        return;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&nh_off, sizeof(nh_off), &skb->network_header);
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + nh_off) < 0)
        return;

    key.saddr = ip.saddr;
    key.daddr = ip.daddr;
    key.proto = ip.protocol;
    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
        u16 ports[2] = {};
        bpf_probe_read_kernel(&ports, sizeof(ports), head + nh_off + ip.ihl * 4);
        key.sport = ntohs(ports[0]);
        key.dport = ntohs(ports[1]);
    }

    val = flows.lookup_or_try_init(&key, &zero);
    if (!val)
        return;
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, len);
    val->last_ns = now;
}

TRACEPOINT_PROBE(net, net_dev_queue)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    u64 key = (u64)skb, now;

    if (!on_target(skb))
        return 0;
    now = bpf_ktime_get_ns();
    enq_ts.update(&key, &now);
    count_flow(skb, args->len, now);
    return 0;
}

TRACEPOINT_PROBE(net, net_dev_start_xmit)
{
    u64 key = (u64)args->skbaddr, now, sojourn, epoch;
    u64 *tsp = enq_ts.lookup(&key);
    struct slot *s;
    int idx;

    if (!tsp)
        return 0;
    now = bpf_ktime_get_ns();
    sojourn = now - *tsp;
    enq_ts.delete(&key);

    epoch = now / WINDOW_NS;
    idx = epoch % NSLOTS;
    s = slots.lookup(&idx);
    if (!s)
        return 0;
    // Dequeue for one device queue is serialised by the kernel, so the slot
    // can be updated without atomics.
    if (s->epoch != epoch) {
        s->epoch = epoch;
        s->count = 0;
        s->sum_ns = 0;
        s->min_ns = sojourn;
        s->max_ns = sojourn;
    }
    s->count += 1;
    s->sum_ns += sojourn;
    if (sojourn < s->min_ns)
        s->min_ns = sojourn;
    if (sojourn > s->max_ns)
        s->max_ns = sojourn;
    return 0;
}
