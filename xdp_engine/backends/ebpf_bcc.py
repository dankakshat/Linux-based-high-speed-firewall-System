"""Real Linux eBPF/XDP backend driven completely from Python via BCC."""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import sys
import threading
import time
from typing import Any

from ..models import BlockedIP, EngineStats, OperatingMode, SecurityEvent
from ..utils import ip_to_u32
from .base import PacketBackend

try:
    from bcc import BPF  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    BPF = None


# Embedded XDP kernel program compiled at runtime by Python BCC on Linux.
_XDP_BPF_SOURCE = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

struct block_entry_t {
    u64 hits;
    u64 expires_ns;
};

struct scan_track_t {
    u64 window_start_ns;
    u32 syn_count;
    u32 last_port;
    u32 unique_ports;
};

struct net_event_t {
    u32 src_ip;
    u32 event_kind; // 1 = port_scan, 2 = syn_flood
    u32 metric;
};

BPF_HASH(blocked_ips, u32, struct block_entry_t, 1000000);
BPF_HASH(allowed_ips, u32, u8, 4096);
BPF_HASH(scan_tracker, u32, struct scan_track_t, 65536);
BPF_ARRAY(stats_map, u64, 5);   // 0:dropped, 1:passed, 2:tcp, 3:udp, 4:icmp
BPF_ARRAY(mode_map, u32, 1);    // 0:detect, 1:enforce
BPF_PERF_OUTPUT(net_events);

static __always_inline void inc_stat(u32 idx) {
    u64 *val = stats_map.lookup(&idx);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_stat(1);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = bpf_ntohl(ip->saddr);

    if (ip->protocol == IPPROTO_TCP) inc_stat(2);
    else if (ip->protocol == IPPROTO_UDP) inc_stat(3);
    else if (ip->protocol == IPPROTO_ICMP) inc_stat(4);

    if (allowed_ips.lookup(&src_ip)) {
        inc_stat(1);
        return XDP_PASS;
    }

    u32 zero = 0;
    u32 *mode_ptr = mode_map.lookup(&zero);
    u32 enforce = mode_ptr ? *mode_ptr : 0;

    struct block_entry_t *blk = blocked_ips.lookup(&src_ip);
    if (blk) {
        u64 now = bpf_ktime_get_ns();
        if (blk->expires_ns == 0 || now < blk->expires_ns) {
            __sync_fetch_and_add(&blk->hits, 1);
            if (enforce) {
                inc_stat(0);
                return XDP_DROP;
            }
        }
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end && tcp->syn && !tcp->ack) {
            u64 now = bpf_ktime_get_ns();
            u16 dport = bpf_ntohs(tcp->dest);
            struct scan_track_t *st = scan_tracker.lookup(&src_ip);
            if (!st) {
                struct scan_track_t fresh = {now, 1, dport, 1};
                scan_tracker.update(&src_ip, &fresh);
            } else {
                if (now - st->window_start_ns > 5000000000ULL) {
                    st->window_start_ns = now;
                    st->syn_count = 1;
                    st->last_port = dport;
                    st->unique_ports = 1;
                } else {
                    st->syn_count += 1;
                    if (st->last_port != dport) {
                        st->last_port = dport;
                        st->unique_ports += 1;
                    }
                    if (st->unique_ports == 15) {
                        struct net_event_t evt = {src_ip, 1, st->unique_ports};
                        net_events.perf_submit(ctx, &evt, sizeof(evt));
                    } else if (st->syn_count == 250) {
                        struct net_event_t evt = {src_ip, 2, st->syn_count};
                        net_events.perf_submit(ctx, &evt, sizeof(evt));
                    }
                }
            }
        }
    }

    inc_stat(1);
    return XDP_PASS;
}
"""


class _BlockEntry(ctypes.Structure):
    _fields_ = [("hits", ctypes.c_uint64), ("expires_ns", ctypes.c_uint64)]


class _NetEvent(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("event_kind", ctypes.c_uint32),
        ("metric", ctypes.c_uint32),
    ]


def is_bcc_available() -> bool:
    """Return True if running on Linux with root privileges and BCC installed."""
    return (
        sys.platform.startswith("linux")
        and BPF is not None
        and getattr(os, "geteuid", lambda: 1)() == 0
    )


class BccXdpBackend(PacketBackend):
    """Linux XDP packet filter managed via Python BCC."""

    name = "ebpf-bcc"

    def __init__(self) -> None:
        if BPF is None:
            raise RuntimeError("python3-bcc is not installed on this system.")
        self._bpf: Any = None
        self._interface: str = ""
        self._mode = OperatingMode.DETECT
        self._lock = threading.Lock()
        self._meta: dict[str, tuple[str, float, float]] = {}
        self._pending_events: list[SecurityEvent] = []
        self._last_dropped = 0
        self._last_stats_ts = time.time()

    def attach(self, interface: str) -> None:
        self._interface = interface
        self._bpf = BPF(text=_XDP_BPF_SOURCE)
        fn = self._bpf.load_func("xdp_filter", BPF.XDP)
        self._bpf.attach_xdp(interface, fn, 0)
        self._bpf["net_events"].open_perf_buffer(self._on_perf_event)
        self.set_mode(self._mode)

    def detach(self) -> None:
        if self._bpf is not None and self._interface:
            try:
                self._bpf.remove_xdp(self._interface, 0)
            finally:
                self._bpf = None

    def _on_perf_event(self, _cpu: int, data: Any, _size: int) -> None:
        evt = ctypes.cast(data, ctypes.POINTER(_NetEvent)).contents
        src_ip = socket.inet_ntoa(struct.pack("!I", evt.src_ip))
        kind = "port_scan" if evt.event_kind == 1 else "syn_flood"
        with self._lock:
            self._pending_events.append(
                SecurityEvent(
                    event_type=kind,
                    src_ip=src_ip,
                    payload=f"kernel_metric={evt.metric}",
                    metadata={"metric": evt.metric},
                )
            )

    def set_mode(self, mode: OperatingMode) -> None:
        self._mode = mode
        if self._bpf is None:
            return
        mode_map = self._bpf["mode_map"]
        mode_map[ctypes.c_uint32(0)] = ctypes.c_uint32(
            1 if mode == OperatingMode.ENFORCE else 0
        )

    def block_ip(self, ip: str, ttl_seconds: int = 600, reason: str = "manual") -> None:
        key = ctypes.c_uint32(ip_to_u32(ip))
        now_wall = time.time()
        expires_wall = 0.0 if ttl_seconds <= 0 else now_wall + ttl_seconds
        expires_ns = (
            0
            if ttl_seconds <= 0
            else int(time.monotonic_ns() + ttl_seconds * 1_000_000_000)
        )
        with self._lock:
            self._meta[ip] = (reason, now_wall, expires_wall)
            if self._bpf is not None:
                self._bpf["blocked_ips"][key] = _BlockEntry(0, expires_ns)

    def unblock_ip(self, ip: str) -> bool:
        key = ctypes.c_uint32(ip_to_u32(ip))
        with self._lock:
            existed = ip in self._meta
            self._meta.pop(ip, None)
            if self._bpf is not None:
                try:
                    del self._bpf["blocked_ips"][key]
                    existed = True
                except KeyError:
                    pass
            return existed

    def allow_ip(self, ip: str) -> None:
        key = ctypes.c_uint32(ip_to_u32(ip))
        if self._bpf is not None:
            self._bpf["allowed_ips"][key] = ctypes.c_uint8(1)

    def unallow_ip(self, ip: str) -> bool:
        key = ctypes.c_uint32(ip_to_u32(ip))
        if self._bpf is None:
            return False
        try:
            del self._bpf["allowed_ips"][key]
            return True
        except KeyError:
            return False

    def list_blocked(self) -> list[BlockedIP]:
        now = time.time()
        result: list[BlockedIP] = []
        with self._lock:
            for ip, (reason, blocked_at, expires_at) in self._meta.items():
                if expires_at > 0 and now >= expires_at:
                    continue
                hits = 0
                if self._bpf is not None:
                    try:
                        entry = self._bpf["blocked_ips"][ctypes.c_uint32(ip_to_u32(ip))]
                        hits = int(entry.hits)
                    except KeyError:
                        pass
                result.append(
                    BlockedIP(
                        ip=ip,
                        reason=reason,
                        blocked_at=blocked_at,
                        expires_at=expires_at,
                        hits=hits,
                        enforced=(self._mode == OperatingMode.ENFORCE),
                    )
                )
        return sorted(result, key=lambda item: item.blocked_at, reverse=True)

    def get_stats(self) -> EngineStats:
        if self._bpf is None:
            return EngineStats()
        stats_map = self._bpf["stats_map"]
        dropped = int(stats_map[ctypes.c_uint32(0)].value)
        passed = int(stats_map[ctypes.c_uint32(1)].value)
        tcp = int(stats_map[ctypes.c_uint32(2)].value)
        udp = int(stats_map[ctypes.c_uint32(3)].value)
        icmp = int(stats_map[ctypes.c_uint32(4)].value)

        now = time.time()
        dt = max(0.1, now - self._last_stats_ts)
        rate = max(0.0, (dropped - self._last_dropped) / dt)
        self._last_dropped = dropped
        self._last_stats_ts = now

        return EngineStats(
            dropped=dropped,
            passed=passed,
            tcp=tcp,
            udp=udp,
            icmp=icmp,
            drop_rate_pps=round(rate, 2),
        )

    def poll_events(self) -> list[SecurityEvent]:
        if self._bpf is not None:
            self._bpf.perf_buffer_poll(timeout=5)
        with self._lock:
            events = list(self._pending_events)
            self._pending_events.clear()
        return events

    def purge_expired(self) -> list[str]:
        now = time.time()
        expired: list[str] = []
        with self._lock:
            for ip, (_, _, expires_at) in list(self._meta.items()):
                if expires_at > 0 and now >= expires_at:
                    expired.append(ip)
        for ip in expired:
            self.unblock_ip(ip)
        return expired
