# eBPF Rate Limiter Architecture

This document describes the design and implementation of the eBPF-based rate limiter used in the Marlin CVM platform. The rate limiter is designed to provide high-performance, token bucket-based bandwidth throttling for instances running within the CVM subnet.

## Overview

The rate limiter enforces bandwidth quotas by inspecting outgoing network traffic at the earliest possible stage in the Linux networking stack using eBPF XDP (eXpress Data Path). It consists of two main components:
1. **eBPF XDP Program (`limiter-ebpf`)**: The data plane that intercepts packets, manages token buckets, and drops or passes packets.
2. **Control Plane Server (`limiter-server`)**: A user-space HTTP server that manages rate limiting configurations and populates the eBPF maps.

By running at the XDP layer, the rate limiter avoids the overhead of traversing the standard Linux networking stack (like skb allocations), ensuring minimal latency and high throughput.

## Data Plane: eBPF XDP Program

The eBPF program (`operator/limiter-ebpf/limiter.c`) is attached to the network interface of the Limiter VM. It implements a token bucket algorithm to rate-limit traffic based on the source IPv4 address.

### eBPF Maps

The XDP program relies on two pinned BPF hash maps to share state with the user-space control plane:

*   **`config_map` (Hash Map)**:
    *   **Key**: Source IPv4 address (`__u32`).
    *   **Value**: `struct rate_config` containing:
        *   `rate`: The rate at which tokens (bytes) are added (scaled per $2^{30}$ ns).
        *   `fill_time`: The maximum time delta allowed for refilling tokens (scaled in $2^{10}$ ns), used to clamp the token accumulation.
*   **`state_map` (Hash Map)**:
    *   **Key**: Source IPv4 address (`__u32`).
    *   **Value**: `struct bucket_state` containing:
        *   `lock`: A `bpf_spin_lock` to prevent race conditions during concurrent packet processing for the same IP.
        *   `last_time`: The timestamp of the last packet processed (scaled in $2^{10}$ ns).
        *   `tokens`: The current number of available tokens (bytes) in the bucket.

### Packet Processing Logic

1.  **Parsing**: When a packet arrives, the XDP program parses the Ethernet header to ensure it's an IPv4 packet. (Currently, IPv6 packets are passed through unhindered).
2.  **Lookup**: It extracts the source IP address and looks it up in the `config_map`. If no configuration exists for the IP, the packet is immediately passed (`XDP_PASS`).
3.  **State Retrieval**: It looks up the current token bucket state for the IP in the `state_map`.
4.  **Token Refill**:
    *   It acquires a spin lock to safely update the bucket.
    *   It calculates the time elapsed (`delta`) since `last_time`.
    *   If `last_time` is 0 (first packet), it defaults to a delta of roughly 1 second.
    *   The `delta` is clamped to the configured `fill_time` to prevent overflow and enforce a maximum bucket capacity (`MAX_CAPACITY` is 1 TB).
    *   New tokens are calculated and added to the bucket (`delta * rate >> 20`).
5.  **Enforcement**:
    *   If the available `tokens` are greater than or equal to the packet length (`pkt_len`), the packet length is subtracted from the bucket, and the packet is allowed (`XDP_PASS`).
    *   If there are insufficient tokens, the packet is dropped (`XDP_DROP`).
6.  **Update**: The `last_time` is updated, and the spin lock is released.

## Control Plane: Limiter Server

The control plane (`operator/limiter-server/src/main.rs`) is an Axum-based HTTP server running on the Limiter VM. It is responsible for dynamically updating the rate limits without requiring a restart of the data plane.

The server interacts with the pinned eBPF maps located at `/sys/fs/bpf/xdp/globals/config_map` and `/sys/fs/bpf/xdp/globals/state_map`.

### API Endpoints

The server exposes a REST API on port `3000`:

*   **`POST /add`**:
    *   **Payload**: `{"ip": "<ipv4>", "rate": <bytes_per_second>}`
    *   **Action**: Calculates the necessary `fill_time` to achieve a 1 TiB maximum capacity over time. It adds the configuration to the `config_map` and initializes the IP's token bucket in the `state_map` with a `START_CAPACITY` of 1,000,000 bytes. The entry is also persisted to `ratelimits.json`.
    *   **Idempotency Note**: This endpoint is effectively an "upsert". While repeated calls succeed, **it is not strictly idempotent regarding state**, as calling it on an existing IP will reset its token bucket back to `START_CAPACITY`.
*   **`POST /remove`**:
    *   **Payload**: `{"ip": "<ipv4>"}`
    *   **Action**: Removes the IP from both the `config_map` and the `state_map`, and deletes the entry from the persistent `ratelimits.json` file.
    *   **Idempotency Note**: This endpoint is fully idempotent. Calling it for an IP that does not exist will safely ignore the missing entries, log a warning, and succeed.
*   **`GET /list`**:
    *   **Action**: Iterates through the `config_map` and `state_map` to return the real-time status of all tracked IPs. This includes the configured rate, fill time, current token count, and last seen timestamp. This is particularly useful for monitoring bandwidth consumption and debugging.
    *   **Idempotency Note**: Safe and idempotent (read-only endpoint).

### Persistence

To survive reboots or service restarts, the `limiter-server` maintains a `ratelimits.json` file. On startup, the server reads this file and automatically re-populates the eBPF `config_map` and `state_map` with the saved configurations.

## Deployment

The eBPF program and the control plane server are integrated into a custom NixOS image via `operator/setup-aws/limiter.nix`.
*   The `limiter-ebpf` service compiles the C code and loads the XDP program onto the Limiter VM's network interface.
*   The `limiter-server` service starts the HTTP control plane, ensuring it runs *after* the eBPF maps have been pinned and initialized by the `limiter-ebpf` service.
