# Internals

This document covers how the major subsystems fit together, the context
that cannot be found in the code alone.

- [Boot procedure](#boot-procedure)
- [Tasks](#tasks)
- [Networking](#networking)
- [TCP implementation](#tcp-implementation)
- [RAM fs](#ram-fs)

For the verification mechanisms (lockdep, scheduler invariants, callout
telemetry, UBSan, self-tests) see [debugging.md](debugging.md).

## Boot procedure

OpenSBI firmware runs in M-mode and hands control to the kernel entry point
at `arch/riscv64/entry.c`. The entry code saves the FDT pointer from `a1`,
sets up the initial stack, zeros BSS, and jumps to `kernel_init()` in
`kernel/init/main.c`.

Early boot parses the Flattened Device Tree (FDT) to discover hardware:
PLIC base, UART base, VirtIO-mmio slots, timebase frequency, and DRAM
layout. All MMIO addresses are resolved from the FDT with fallbacks to the
QEMU `virt` machine defaults.

The `kernel_init` function calls subsystem initialization in dependency
order:

1. `arch_init()` brings up the UART (so `printk` works for early
   diagnostics), installs the PLIC-backed trap vector via the
   `irqchip` vtable, and hardens CSR state (clears `sstatus.SUM` and
   `sstatus.MXR`).
2. `time_init()` configures the timebase from the FDT.
3. `mem_init()` configures the dynamic region, calls `paging_init()`
   (which builds Sv39 three-level identity-mapped page tables using
   2 MiB superpages, activates `satp`, and flushes the TLB), then
   calls `kvalloc_init()` to set up the kernel heap.
4. `initgraph_run(INIT_FLAG_PRIMARY)` executes a DAG-based dependency
   graph of init tasks using Kahn's topological sort (for example
   scheduler -> watchdog / loadbal / tcp -> mdns).

After init, the kernel creates core service tasks (packet receive, TCP
maintenance, web serving, optional probes) and enters the scheduler loop.

## Tasks

Mazu ships only hard-RT scheduling profiles:

- Default SMP hard-RT profile (`configs/defconfig`)
- RT validation profile (`configs/rt_defconfig`)

Timer-driven quanta force reschedule points at every priority level. When
`CONFIG_SMP` is enabled, each hart has its own run queue with a per-CPU
lock, an idle-steal path for pull migration, and a periodic load balancer
using exponential-decay estimation. Optional EEVDF fair scheduling
(`CONFIG_SCHED_EEVDF`) bounds wake-to-run latency within each priority
level. Deadline scheduling and mixed-criticality extensions build on the
same SMP-first model. Scheduling domains (`struct sched_domain`) enforce
per-group CPU budgets with automatic refill.

Kernel services are driven by scheduler tasks created during boot. Typical
long-lived tasks include:

- Packet receive path (`netdev` -> protocol dispatch)
- TCP retransmission/callout maintenance
- Activity watchdog (detects hung tasks after 5s inactivity)
- SMP load balancer (periodic rebalancing across harts)
- HTTP/WebSocket request handling

## Networking

Networking is a core subsystem in Mazu because the kernel is intended for
connected embedded systems rather than isolated firmware. On QEMU `virt`,
networking is provided by the virtio-mmio net driver
(`drivers/net/virtio_mmio.c`) through the `netdev` abstraction layer. The
RX interrupt path pushes frames into the `netdev` input queue; scheduler
tasks drain that queue and pass packets up the protocol stack.

The receive task checks the queue, validates packet structure at each
layer, and demultiplexes to ARP/ICMP/TCP (plus optional UDP-based
protocols). Replies are usually emitted during packet handling; TCP also
stages sent data in retransmission queues.

The routing table is initialized from `rootfs/config.txt` in `kernel_init`
(or DHCP-derived values when enabled). At transmit time, route lookup
chooses interface/gateway; unresolved L2 next-hop addresses trigger ARP
resolution before payload transmission.

## TCP implementation

The TCP subsystem is the most complex part of Mazu and is documented in
the most detail here.

References:

- [RFC 1323: TCP Extensions for High Performance](https://www.rfc-editor.org/rfc/rfc1323)
- [RFC 6298: Computing TCP's Retransmission Timer](https://www.rfc-editor.org/rfc/rfc6298)
- [RFC 9293: Transmission Control Protocol (TCP)](https://www.rfc-editor.org/rfc/rfc9293)

### Public API

The essential functions exposed by the TCP subsystem:

```c
/* Server-side (listen/accept) */
struct tcp_conn *tcp_conn_listen(struct ipv4_addr addr, u16 port, struct arena tmp);
struct tcp_conn *tcp_conn_accept(struct tcp_conn *listen_conn);

/* Client-side (active open) */
struct tcp_conn *tcp_conn_connect(struct ipv4_addr remote_addr, u16 remote_port, struct arena tmp);
bool tcp_conn_is_connected(struct tcp_conn *conn);
bool tcp_conn_is_reset(struct tcp_conn *conn);

/* Data transfer and teardown */
struct result_sz tcp_conn_send(struct tcp_conn *conn, struct byte_view payload, bool *peer_closed_conn,
                               struct arena tmp);
struct result_sz tcp_conn_recv(struct tcp_conn *conn, struct byte_buf *buf, bool *peer_closed_conn);
struct result tcp_conn_close(struct tcp_conn **conn, struct arena tmp);
```

The primary consumer of the TCP interface is the web server. For
comparison, the equivalent Berkeley Sockets setup looks like:

```c
sfd = socket(AF_INET, SOCK_STREAM, 0);
bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
listen(sfd, BACKLOG_SIZE);
```

The effect of all three calls is implemented by `tcp_conn_listen` in the
Mazu TCP interface, which takes as arguments an IP address and a port
number. `tcp_conn_listen` returns a connection structure that serves as a
handle for a `LISTEN`-state connection ("listen connection" for short)
that the function creates. This connection structure essentially serves
the purpose of the `sfd` file descriptor in the example above.

Connections can be accepted with `tcp_conn_accept`. The only argument to
`tcp_conn_accept` is a listen connection. If a peer has tried to establish
a connection with the right IP address and port before `tcp_conn_accept`
is called, a `struct tcp_conn` handle for this connection is returned by
`tcp_conn_accept`. Here, the "right" IP address and port number are the
IP address and port number that were passed to `tcp_conn_listen`.
`tcp_conn_accept` can be polled to await a connection.

Note that `tcp_conn_listen` and `tcp_conn_accept` both create a new
connection. After calling each function once and getting a non-`NULL`
return value both times, there exist two connections: one in the `LISTEN`
state and one representing an active connection to a peer. This, in turn,
means a listen connection can be reused indefinitely to accept further
connections. The listen connection is deleted only after calling
`tcp_conn_close` on it.

Three operations can be performed on open connections returned by
`tcp_conn_accept`: sending data to the peer, receiving data from the peer,
and closing the connection. Connections are closed and deleted by
`tcp_conn_close`.

The send and receive functions can be called arbitrarily often.

`tcp_conn_send` takes a connection, a payload of bytes, and a pointer to a
boolean flag indicating whether the peer has closed the connection. If
the peer has closed the connection, it will not acknowledge new data;
callers should check this flag periodically and close the connection when
it is set. The return value indicates the number of bytes transmitted.
TCP uses a sliding-window approach to traffic control. If the caller
sends data faster than the peer can acknowledge, the window fills up, the
implementation stops transmitting, and the return value of `tcp_conn_send`
is smaller than the payload length.

`tcp_conn_send` internally splits the payload into fragments small enough
to fit one Ethernet frame. Larger TCP segments could rely on IP-layer
fragmentation, but that has a downside: TCP retransmits at the segment
level, so losing a single IP fragment forces retransmission of the entire
segment. Fragmenting at the TCP level avoids this overhead. After
splitting the payload, each fragment is transmitted immediately and also
added to the send buffer queue (SBQ) of the connection for retransmission
(see below).

`tcp_conn_recv` takes a connection, a destination buffer, and the
peer-closed flag. The TCP implementation buffers all received data
internally. On each call, available data is copied from the internal
circular buffer into the destination buffer. The amount copied is limited
by whichever is smaller: available data or destination capacity. The
return value is the byte count copied; `0` means no data is available.

The TCP subsystem also supports outbound (active open) connections via
`tcp_conn_connect`. This allocates an ephemeral port (49152-65535), sends
a SYN, and returns a handle in SYN_SENT state. The caller polls
`tcp_conn_is_connected` until the three-way handshake completes (or
`tcp_conn_is_reset` to detect failure). Once connected, `tcp_conn_send`
and `tcp_conn_recv` work identically to server-side connections. This
enables the kernel to make outbound HTTP requests, which is required for
the AI assistant use case.

A note on the peer-closed flag: the Berkeley Sockets API returns `-EOF`
from `read(2)` when a connection closes, packing error codes into the
negative range of non-negative return values. Mazu rejects this practice.
A separate boolean flag is a better fit because the condition ("has the
peer closed?") does not need to be checked on every call, only eventually,
to avoid infinite loops.

### The TCP state machine

The TCP protocol is built around a per-connection state machine. RFC
9293 contains the canonical dense diagram; the Mazu rendering below
uses Unicode box-drawing throughout and splits the machine into two
flow diagrams (open and close) plus a transition table for the
multi-way joins that are awkward to draw.

Open path. Passive (server) and active (client) paths converge on
`ESTABLISHED`.

```plain
                  ┌────────────┐
                  │   CLOSED   │
                  └──────┬─────┘
       passive OPEN      │      active OPEN
       create TCB        │      create TCB, snd SYN
                  ┌──────┴──────┐
                  ▼             ▼
           ┌────────────┐  ┌────────────┐
           │   LISTEN   │  │  SYN-SENT  │
           └──────┬─────┘  └──────┬─────┘
              rcv SYN          rcv SYN,ACK
              snd SYN,ACK      snd ACK
                  ▼                │
           ┌────────────┐          │
           │  SYN-RCVD  │          │
           └──────┬─────┘          │
            rcv ACK of SYN         │
                  ▼                ▼
                  └───────┬────────┘
                          ▼
                  ┌────────────┐
                  │ ESTABLISHED│
                  └────────────┘
```

Close path. Active close on the left (local `CLOSE` first), passive
close on the right (peer sends FIN first). `FIN-WAIT-1` is the
multi-way join; its outgoing transitions are listed in the table that
follows.

```plain
                  ┌────────────┐
                  │ ESTABLISHED│
                  └──────┬─────┘
       CLOSE             │             rcv FIN
       snd FIN           │             snd ACK
                  ┌──────┴──────┐
                  ▼             ▼
           ┌────────────┐  ┌────────────┐
           │ FIN-WAIT-1 │  │ CLOSE-WAIT │
           └──────┬─────┘  └──────┬─────┘
              (see table)         │ CLOSE
                  │               │ snd FIN
                  │               ▼
                  │        ┌────────────┐
                  │        │  LAST-ACK  │
                  │        └──────┬─────┘
                  │               │ rcv ACK of FIN
                  ▼               ▼
           ┌────────────┐  ┌────────────┐
           │ TIME-WAIT  │  │   CLOSED   │
           └──────┬─────┘  └────────────┘
            2MSL timeout
            delete TCB
                  ▼
           ┌────────────┐
           │   CLOSED   │
           └────────────┘
```

Outgoing transitions from `FIN-WAIT-1`:

| Event | Action | Next state |
|-------|--------|------------|
| rcv ACK of our FIN | --- | `FIN-WAIT-2` |
| rcv peer FIN (before ACK of ours) | snd ACK | `CLOSING` |
| rcv peer FIN with ACK of ours | snd ACK | `TIME-WAIT` |

Outgoing transitions from `FIN-WAIT-2` and `CLOSING`:

| From | Event | Action | Next state |
|------|-------|--------|------------|
| `FIN-WAIT-2` | rcv FIN | snd ACK | `TIME-WAIT` |
| `CLOSING` | rcv ACK of our FIN | --- | `TIME-WAIT` |

Mazu's implementation tracks every named state explicitly. When a
segment arrives from the IP layer, the corresponding connection is
looked up and dispatched through a per-state handler
(`tcp_handle_receive_*`). The handlers manage transitions, allocate
and free connection and receive-buffer storage, and update the
per-connection variables.

Handling each state separately is verbose, and coalescing similar
behavior into a generic handler that treats per-state differences as
special cases would reduce code size. The trade-off is deliberate:
per-state handlers mirror the RFC specification directly, making the
code straightforward to verify and debug. Common behavior is factored
into the `tcp_conn_update_*` helpers where obvious.

### Reception and circular receive buffers

A TCP connection receives data in the `ESTABLISHED` state. A dedicated
task polls the network device; when IP data arrives, the IP layer extracts
the TCP/IP pseudo header and passes it to `tcp_handle_packet`, which
invokes the per-state handlers described above.

When data is received by an `ESTABLISHED` TCP connection, it is appended
to a circular buffer. The buffer is allocated right before transitioning
the connection to the `ESTABLISHED` state, and it has a fixed size. The
TCP implementation advertises the amount of available space to the peer
with the window size field of the TCP header. The advertised window size
decreases while the circular buffer fills up, which discourages the peer
from sending more data. The window size increases again after the caller
has copied received data out of the circular buffer via `tcp_conn_recv`.

### Send buffer queues (SBQs) and retransmissions

A key function of TCP, besides traffic control, is ensuring reliable
delivery.

`tcp_conn_send` calls the internal `tcp_send_segment` function, which
allocates a send buffer (SB), a data structure designed to make prepending
protocol headers easy as the packet moves down the network stack. The
payload is copied into the send buffer, and the buffer is appended to the
connection's send buffer queue (SBQ). The SBQ is a linked list where each
node carries timestamps for retransmission timing and the ACK number that
must arrive before the segment can be freed.

`tcp_send_segment` calls into the IP layer to transmit the segment
immediately after adding the payload to the retransmission queue. A
dedicated scheduler task periodically calls `tcp_poll_retransmit`, which
iterates over all active connections and their SBQs. Each node in the SBQ
is processed as follows (where one node represents one segment waiting for
retransmission or acknowledgment):

1. If the ACK for the segment has arrived since the last poll, the
   segment data is freed and the node is removed from the queue.
2. If a maximum number of retransmission attempts has been reached, the
   segment data is freed and the node is removed from the queue.
3. If neither of the two above conditions holds, and the retransmission
   timeout of the segment has expired, the segment is retransmitted. The
   timeout doubles on each retransmission (exponential backoff).

The TCP timestamps option (TSopt) measures the round-trip time (RTT) of
each connection. The base retransmission timeout (RTO) is computed
dynamically from RTT measurements using the algorithm in RFC 6298. If
TSopt is absent, a default RTO of 1 second is used (unlikely in practice;
TSopt has been standard since 1992).

### Congestion control

TCP congestion control is factored into a pluggable vtable
(`struct tcp_cc_ops`) with three callbacks: `on_ack`, `on_dup_ack`, and
`on_timeout`. The default implementation is Reno (RFC 5681): slow start,
congestion avoidance, fast recovery on 3 duplicate ACKs, and exponential
backoff on RTO. The initial congestion window is 10 segments (RFC 6928).
The send path uses `min(rwnd, cwnd)` as the effective window. Per-connection
`cwnd` and `ssthresh` are exposed in the `/api/tcp` JSON endpoint. The
vtable design allows future replacement with Cubic or BBR without touching
the TCP state machine.

### Memory management and allocators

TCP frequently needs new connection structures and data buffers, most of
which are short-lived. The implementation uses two allocation strategies.

Connection structures live in a global array. Each entry has an in-use
flag; allocation scans for an unused slot. This is simple, fast, and
provides good data locality. The array also supports the frequent
full-table scans required by retransmission polling and connection
cleanup, something a pool allocator is not designed for.

A connection structure is allocated when the TCP handshake begins, but no
data buffers are allocated at that point. Receive buffers are allocated
from a fixed-size pool after the handshake completes. The pool allocator
has low overhead and strong locality.

Send buffers in the retransmission queue (SBQ) are allocated from their
own pool allocator. Any number of send buffers can be allocated for a
single connection, depending on how much data the caller is transmitting
and how much remains unacknowledged. Send buffers are freed based on the
rules above.

The pool allocators, in turn, are backed by big contiguous allocations
from `kvalloc`. All of them are allocated at boot. This strategy leads to
low fragmentation and speedy allocations.

## RAM fs

The RAM file system (ramfs) stores content served by the web server. The
core data structure is `struct ram_fs_node`:

```c
struct ram_fs_node {
    /* First node in the directory if this node is of type RAM_FS_TYPE_DIR. */
    struct ram_fs_node *first;
    /* Next node in the same directory as this node. A linked list. */
    struct ram_fs_node *next;
    enum ram_fs_node_type type;
    struct str name;
    /* Data of the file if this node is of type RAM_FS_TYPE_FILE. */
    struct byte_buf data;
    /* Pointer back to parent FS. */
    struct ram_fs *fs;
};
```

An instance of a ramfs is defined by the `struct ram_fs`:

```c
struct ram_fs {
    struct alloc data_alloc;
    struct pool node_alloc;
    struct arena scratch;
    struct ram_fs_node *root;
};
```

The `data_alloc` is an abstract allocator (could be any) that's used to
allocate buffers for file data and the names of nodes. The `node_alloc`
is a pool allocator that hands out fixed-size chunks of memory for
`struct ram_fs_node` allocations. A ramfs is created by calling
`ram_fs_new`. This function takes the `data_alloc` as its only argument.
The `node_alloc` is then allocated from the `data_alloc`.

A separate allocator for node names would make sense because the
allocation patterns of names and data buffers differ. However, names vary
in size, so a pool allocator would waste memory (each slot must be the
maximum size). Instead, `data_alloc` serves all variable-length
allocations.

The `first` and `next` fields of `struct ram_fs_node` form a tree.
`next` links nodes within the same directory as a singly linked list;
`first` is set only on directory nodes and points to the head of that
list. Subsequent children are reached by following `next` pointers.

Legend: each box is a `struct ram_fs_node`. `next →` is the sibling
pointer, `first ↓` is the child pointer, `∅` is a `NULL` terminator.

```plain
                   ┌──────────────────────┐
                   │      /web (dir)      │ next → ∅
                   └──────────┬───────────┘
                        first │
                              ▼
                   ┌──────────────────────┐  next   ┌──────────────────────┐
                   │ /web/index.html      │ ──────▶ │  /web/public (dir)   │ next → ∅
                   └──────────────────────┘         └──────────┬───────────┘
                       first → ∅                          first │
                                                                ▼
                                                     ┌──────────────────────┐
                                                     │ /web/public/style.css│ next → ∅
                                                     └──────────────────────┘
                                                         first → ∅
```

Internally, paths are represented by the `struct path_name` structure. It
looks like this:

```c
struct path_name {
    struct str src;
    /* The path '/' is represented by a `struct path_name` where
     * `n_components` is 0, the empty path. */
    sz n_components;
    struct str *components;
    bool is_absolute;
};
```

`path_name_parse` takes a path string and an arena allocator, and returns
a `struct path_name`. The `src` field holds a full, unmodified copy of
the path string (allocated from the arena). The `components` array
contains string slices pointing into `src`, one per path component, with
slashes stripped.

This structure makes path lookup trivial and keeps parsing cleanly
separated from tree traversal, two concerns that are easier to verify
independently.
