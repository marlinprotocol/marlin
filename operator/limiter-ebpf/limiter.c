#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#define NUM_ENTRIES 65536
#define START_CAPACITY 1000000ULL     // 1 MB
#define MAX_CAPACITY 1000000000000ULL // 1 TB

struct rate_config {
  __u64 rate;      // tokens (bytes) per 2^30 ns
  __u64 fill_time; // in 2^10 ns
};

struct bucket_state {
  struct bpf_spin_lock lock;
  __u64 last_time; // in 2^10 ns
  __u64 tokens;
};

// Map for configuration (pinned, populated by userspace)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NUM_ENTRIES);
  __type(key, __u32); // Source IP
  __type(value, struct rate_config);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

// Map for keeping track of token buckets
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, NUM_ENTRIES);
  __type(key, __u32); // Source IP
  __type(value, struct bucket_state);
} state_map SEC(".maps");

SEC("xdp")
int xdp_rate_limit(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  // Only handle IPv4
  // WARN: this currently passes IPv6 through
  // We rely on not enabling it in the VPC, revisit if this changes
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // Parse IP header
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // Get source IP
  __u32 src_ip = ip->saddr;

  // Lookup rate
  struct rate_config *rate = bpf_map_lookup_elem(&config_map, &src_ip);
  if (!rate) {
    // No rate limit configured for this IP
    return XDP_PASS;
  }

  // Lookup or initialize bucket state
  struct bucket_state *state = bpf_map_lookup_elem(&state_map, &src_ip);
  if (!state) {
    struct bucket_state new_state = {0};
    new_state.last_time = bpf_ktime_get_ns() >> 10;
    new_state.tokens = START_CAPACITY;

    // Try to update. If it fails (race condition), lookup again.
    bpf_map_update_elem(&state_map, &src_ip, &new_state, BPF_NOEXIST);
    state = bpf_map_lookup_elem(&state_map, &src_ip);
    if (!state) {
      // Should not happen, but safe fallback
      return XDP_ABORTED;
    }
  }

  bpf_spin_lock(&state->lock);

  __u64 now = bpf_ktime_get_ns() >> 10;
  __u64 pkt_len = (__u64)(data_end - data);

  // Calculate time and clamp to prevent overflows
  __u64 delta = now - state->last_time;
  if (delta > rate->fill_time) {
    delta = rate->fill_time;
  }

  // Calculate tokens to add
  __u64 tokens_to_add = delta * rate->rate >> 20;

  state->tokens += tokens_to_add;
  if (state->tokens > MAX_CAPACITY) {
    state->tokens = MAX_CAPACITY;
  }

  // Update time
  // only if tokens were added, to avoid perma dropping fractional tokens
  if (tokens_to_add > 0) {
    state->last_time = now;
  }

  // Check if we have enough tokens
  int action = XDP_DROP;
  if (state->tokens >= pkt_len) {
    state->tokens -= pkt_len;
    action = XDP_PASS;
  }

  bpf_spin_unlock(&state->lock);

  return action;
}

char LICENSE[] SEC("license") = "GPL";
