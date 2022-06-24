/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <linux/bpf.h>
#include <linux/in.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include "headers/bpf_endian.h"
#include "headers/common.h"

#define SYS_REJECT 0
#define SYS_PROCEED 1
#define DEFAULT_MAX_EBPF_MAP_ENNTRIES 65536
#define AF_INET 2
#define AF_INET6 10

char __license[] SEC("license") = "Dual BSD/GPL";

struct V4_key
{
  __be32 address;     /* Service virtual IPv4 address  4*/
  __be16 dport;       /* L4 port filter, if unset, all ports apply   */
  __u16 backend_slot; /* Backend iterator, 0 indicates the svc frontend  2*/
};

struct lb4_service
{
  union
  {
    __u32 backend_id;       /* Backend ID in lb4_backends */
    __u32 affinity_timeout; /* In seconds, only for svc frontend */
    __u32 l7_lb_proxy_port; /* In host byte order, only when flags2 &&
                               SVC_FLAG_L7LOADBALANCER */
  };
  /* For the service frontend, count denotes number of service backend
   * slots (otherwise zero).
   */
  __u16 count;
  __u16 rev_nat_index; /* Reverse NAT ID in lb4_reverse_nat */
  __u8 flags;
  __u8 flags2;
  __u8 pad[2];
};

struct lb4_backend
{
  __be32 address; /* Service endpoint IPv4 address */
  __be16 port;    /* L4 port filter */
  __u8 flags;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct V4_key);
  __type(value, struct lb4_service);
  __uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENNTRIES);
} v4_svc_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct lb4_backend);
  __uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENNTRIES);
} v4_backend_map SEC(".maps");

static __always_inline struct lb4_service *
lb4_lookup_service(struct V4_key *key)
{
  struct lb4_service *svc;

  svc = bpf_map_lookup_elem(&v4_svc_map, key);
  if (svc)
  {
    return svc;
  }

  return NULL;
}

/* Hack due to missing narrow ctx access. */
static __always_inline __be16 port_cast_16(__u32 port)
{
  volatile __u32 castedPort = port;

  return (__be16)castedPort;
}

static __always_inline __be32 port_cast_32(__be16 port)
{
  volatile __u16 castedPort = port;

  return (__be32)castedPort;
}

static __always_inline __u64 sock_select_slot()
{
  return bpf_get_prandom_u32();
}

static __always_inline struct lb4_backend *
__lb4_lookup_backend(__u32 backend_id)
{
  return bpf_map_lookup_elem(&v4_backend_map, &backend_id);
}

static __always_inline struct lb4_service *
__lb4_lookup_backend_slot(struct V4_key *key)
{
  return bpf_map_lookup_elem(&v4_svc_map, key);
}

/* Service translation logic for a local-redirect service can cause packets to
 * be looped back to a service node-local backend after translation. This can
 * happen when the node-local backend itself tries to connect to the service
 * frontend for which it acts as a backend. There are cases where this can break
 * traffic flow if the backend needs to forward the redirected traffic to the
 * actual service frontend. Hence, allow service translation for pod traffic
 * getting redirected to backend (across network namespaces), but skip service
 * translation for backend to itself or another service backend within the same
 * namespace. Currently only v4 and v4-in-v6, but no plain v6 is supported.
 *
 * For example, in EKS cluster, a local-redirect service exists with the AWS
 * metadata IP, port as the frontend <169.254.169.254, 80> and kiam proxy as a
 * backend Pod. When traffic destined to the frontend originates from the kiam
 * Pod in namespace ns1 (host ns when the kiam proxy Pod is deployed in
 * hostNetwork mode or regular Pod ns) and the Pod is selected as a backend, the
 * traffic would get looped back to the proxy Pod. Identify such cases by doing
 * a socket lookup for the backend <ip, port> in its namespace, ns1, and skip
 * service translation.
 */
static __always_inline bool
sock4_skip_xlate_if_same_netns(struct bpf_sock_addr *ctx,
                               const struct lb4_backend *backend)
{
#ifdef BPF_HAVE_SOCKET_LOOKUP
  struct bpf_sock_tuple tuple = {
      .ipv4.daddr = backend->address,
      .ipv4.dport = backend->port,
  };
  struct bpf_sock *sk = NULL;

  switch (ctx->protocol)
  {
  case IPPROTO_TCP:
    sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    break;
  case IPPROTO_UDP:
    sk = sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    break;
  }

  if (sk)
  {
    sk_release(sk);
    return true;
  }
#endif /* BPF_HAVE_SOCKET_LOOKUP */
  return false;
}

static __always_inline struct lb4_backend * __service_lookup(struct V4_key *key)
{
  struct lb4_service *svc;
  struct lb4_service *backend_slot;

  __u32 backend_id = 0;

  svc = lb4_lookup_service(key);
  if (!svc)
  {
    return NULL;
  }

  // Logs are in /sys/kernel/debug/tracing/trace_pipe
  if (backend_id == 0)
  {
    key->backend_slot = (sock_select_slot() % svc->count) + 1;
    backend_slot = __lb4_lookup_backend_slot(key);
    if (!backend_slot)
    {
      return NULL;
    }

    backend_id = backend_slot->backend_id;
    return __lb4_lookup_backend(backend_id);
  }
  return NULL;
}

static __always_inline int __sock4_fwd(struct bpf_sock_addr *ctx)
{
  struct V4_key key = {
      .address = ctx->user_ip4,
      .dport = port_cast_16(ctx->user_port),
      .backend_slot = 0,
  };

  struct lb4_backend *backend;

  backend = __service_lookup(&key);
  if (!backend) { 
    return -ENXIO;
  }

  if (sock4_skip_xlate_if_same_netns(ctx, backend))
  {
    return -ENXIO;
  }

   const char debug_str[] = "Back in the connect prog caught a\
  packet destined for my VIP, directing to backend address: %x and port: %x\n";

  bpf_trace_printk(debug_str, sizeof(debug_str),backend->address, backend->port);

  ctx->user_ip4 = backend->address;
  ctx->user_port = port_cast_32(backend->port);

  return 0;
}

/*
 * Swaps destination and source MAC addresses inside an Ethernet header
 */
// static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
// {
// 	__u8 h_tmp[ETH_ALEN];

// 	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
// 	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
// 	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
// }

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
  __sock4_fwd(ctx);
  return SYS_PROCEED;
}

const volatile int ifindex_out;

SEC("xdp")
int xdp_nodeport_redirect(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct bpf_fib_lookup fib_params = {};
  struct ethhdr *eth = data;
  struct tcphdr *tcph;
  u16 h_proto;
  u64 nh_off;
  u64 tcp_off;

  nh_off = sizeof(*eth);

  struct iphdr *iph = data + nh_off;

  tcp_off = nh_off + sizeof(*iph);

  if (data + tcp_off > data_end)
    return XDP_PASS;

  tcp_off = nh_off + sizeof(*iph);

  h_proto = eth->h_proto;

  if (h_proto == bpf_htons(ETH_P_IP))
  {
    if (iph->protocol != IPPROTO_TCP)
      return XDP_PASS;

    tcph = data + tcp_off;

    // Check header length.
    if (tcph + 1 > (struct tcphdr *)data_end)
    {
      return XDP_PASS;
    }

    struct V4_key key = {
        .address = 0,
        .dport = port_cast_16(tcph->dest),
        .backend_slot = 0,
    };

    struct lb4_service *svc = lb4_lookup_service(&key);
    if (!svc)
    {
      return XDP_PASS;
    }

    // This is how we know the service lookup was actually for a nodeport
    if (svc->flags != 1 && svc->count != 0)
    {
      return XDP_PASS;
    }

    // Lookup clusterIP of the service
    __u32 backend_id = svc->backend_id;
    struct lb4_backend *backend;

    backend = __lb4_lookup_backend(backend_id);
    if (!backend)
    {
      return XDP_PASS;
    }

    key.address = backend->address;
    key.dport = backend->port;
    
    // Proxy straight to backend, to do that lookup backend with same logic as connect 4 prog
    backend = __service_lookup(&key);
    if (!backend) { 
      return XDP_PASS;
    }

    // Now we have an endpoint to route to 

    // Basically perform a DNAT here and then 
    // route to destination if we can
    // // swap_src_dst_mac(eth);
    iph->saddr = iph->daddr;
    iph->daddr = backend->address;
    tcph->source = tcph->dest;
    tcph->dest = port_cast_32(backend->port);

    /* populate the fib_params fields to prepare for the lookup */
		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= 0;
		fib_params.ipv4_dst	= iph->daddr;

    const char debug_str[] = "Hello, world, from BPF! I am in the XDP program. dst IP is %x dest port is %d new dst IP is %x";

    bpf_trace_printk(debug_str, sizeof(debug_str), iph->daddr, bpf_ntohs(tcph->dest), backend->address);
      
    fib_params.ifindex = ctx->ingress_ifindex;

    /* this is where the FIB lookup happens. If the lookup is successful */
    /* it will populate the fib_params.ifindex with the egress interface index */

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    
    const char debug_str2[] = "Looking for route to dst IP %x returned %d";

    bpf_trace_printk(debug_str2, sizeof(debug_str2), iph->daddr, rc);

    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
      /* we are a router, so we need to decrease the ttl */
      //if (h_proto == bpf_htons(ETH_P_IP))
      ip_decrease_ttl(iph);

      const char debug_str4[] = "Redirect to eth src %x and eth dst %x route srcip %x";

      bpf_trace_printk(debug_str4, sizeof(debug_str4), fib_params.smac, fib_params.dmac, fib_params.ipv4_src);

      
      /* set the correct new source and destionation mac addresses */
      /* can be found in fib_params.dmac and fib_params.smac */
      __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
      __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
      /* and done, now we set the action to bpf_redirect_map with fib_params.ifindex which is the egress port as paramater */
      
      //int rrc = bpf_redirect(fib_params.ifindex, 0);

      //const char debug_str3[] = "Redirect to link %d returned %d";

      //bpf_trace_printk(debug_str3, sizeof(debug_str3), fib_params.ifindex, rrc);

      return XDP_PASS;
      break;
    case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
      return XDP_DROP;
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
      /* PASS */
      break;
    }

  }

  return XDP_PASS;
}
