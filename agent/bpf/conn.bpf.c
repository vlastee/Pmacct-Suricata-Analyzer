// pmacct-agent eBPF capture: report every outgoing connection / UDP datagram with the PID.
//
// Attached to the root cgroup (cgroup v2) on the sock_addr hooks, which run in the context of
// the calling process and expose the destination in the stable `struct bpf_sock_addr` UAPI —
// no kernel-struct access, so this object works unchanged across kernel versions (>= 5.8 for
// the ring buffer). Always returns 1 (allow): observation only, never enforcement.
#include <linux/bpf.h>
#include <linux/types.h>

// Minimal stand-ins for libbpf's bpf_helpers.h so the program builds with just the kernel UAPI
// header. Helper numbers are the stable kernel ABI (see include/uapi/linux/bpf.h).
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;

#define AF_INET 2
#define AF_INET6 10

struct event {
    __u32 pid;
    __u32 uid;
    __u16 family;   // AF_INET / AF_INET6
    __u16 proto;    // IPPROTO_TCP (6) / IPPROTO_UDP (17)
    __u16 dport;    // host byte order
    __u16 _pad;
    __u8  daddr[16];
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB: survives DNS bursts between user-space drains
} EVENTS SEC(".maps");

static __always_inline int emit(struct bpf_sock_addr *ctx, __u16 family)
{
    struct event *e = bpf_ringbuf_reserve(&EVENTS, sizeof(*e), 0);
    if (!e)
        return 1; // ring full: drop the observation, never the connection
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->family = family;
    e->proto = (__u16)ctx->protocol;
    e->dport = __builtin_bswap16((__u16)ctx->user_port);
    e->_pad = 0;
    __builtin_memset(e->daddr, 0, sizeof(e->daddr));
    if (family == AF_INET) {
        __u32 a = ctx->user_ip4;
        __builtin_memcpy(e->daddr, &a, 4);
    } else {
        __u32 a[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
        __builtin_memcpy(e->daddr, a, 16);
    }
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 1;
}

SEC("cgroup/connect4") int connect4(struct bpf_sock_addr *ctx) { return emit(ctx, AF_INET); }
SEC("cgroup/connect6") int connect6(struct bpf_sock_addr *ctx) { return emit(ctx, AF_INET6); }
SEC("cgroup/sendmsg4") int sendmsg4(struct bpf_sock_addr *ctx) { return emit(ctx, AF_INET); }
SEC("cgroup/sendmsg6") int sendmsg6(struct bpf_sock_addr *ctx) { return emit(ctx, AF_INET6); }

char LICENSE[] SEC("license") = "GPL";
