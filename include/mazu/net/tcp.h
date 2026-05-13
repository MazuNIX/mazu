/* SPDX-License-Identifier: MIT */
/* Transmission Control Protocol (TCP) implementation.
 *
 * Thread safety: two-level locking. tcp_pool_lock serializes connection-table
 * ownership, timer heap updates, and TCP state-machine transitions that span
 * multiple connections or shared queues. Per-connection conn->lock protects
 * local metadata snapshots such as notify hooks, receive-ready state, accept
 * readiness, and single-connection status reads. Both use irqsave because the
 * network RX trap/IRQ path also enters TCP from high priority. Callers must
 * not hold either lock.
 *
 * Ownership: TCP connections are pool-allocated (fixed-size connection pool).
 * A connection pointer is valid from SYN processing to tcp_free_conn().
 * Callers receive data through tcp_recv() which copies from the per-connection
 * receive buffer; zero-copy reads are not supported.
 */

#ifndef MAZU_NET_TCP_H
#define MAZU_NET_TCP_H

#include <mazu/base.h>
#include <mazu/net/ip_addr.h>
#include <mazu/net/netorder.h>
#include <mazu/net/send_buf.h>
#include <mazu/string.h>
#include <mazu/time.h>

struct result tcp_init(void);

/* Service due TCP timers (retransmit, keep-alive, internal timeout, persist).
 * If the earliest pending timer is still in the future, the fast path returns
 * immediately without taking the coarse TCP pool lock. Call periodically often
 * enough that expired timers are serviced soon after their deadline. After each
 * slow-path scan the internal timer min-heap is rebuilt; tcp_timer_next_ms()
 * then returns the O(1) earliest next-event time across all connections.
 */
struct result tcp_poll_retransmit(struct arena tmp);

/* Return the millisecond timestamp of the earliest pending TCP timer event
 * (retransmit, keep-alive, internal timeout, or persist).  Returns TIME_MS_MAX
 * when no timers are armed.  O(1) - reads the root of the internal min-heap.
 */
u64 tcp_timer_next_ms(void);

/* IP side */

struct tcp_ip_pseudo_header {
    struct ipv4_addr src_addr;
    struct ipv4_addr dest_addr;
    u8 zero;
    u8 protocol;
    net_u16 tcp_length;
};

struct result tcp_handle_packet(struct tcp_ip_pseudo_header pseudo_hdr,
                                struct byte_view segment,
                                struct send_buf sb,
                                struct arena tmp);

/* User interface

 * These functions are meant for using TCP. You are handed internal data here so
 * just don't touch it. Callers are expected to respect this.
 */

struct tcp_conn; /* opaque */

/* Per-connection event notification hooks.
 * Kernel-internal only; consumed by the in-kernel HTTP server, the /net
 * synthetic filesystem, and any other task that needs out-of-band event
 * delivery.  NULL callbacks are skipped.
 * Callbacks are invoked while tcp_pool_lock is held. The hook pointer itself
 * is snapshotted under conn->lock so tcp_conn_set_notify() does not contend on
 * the global TCP lock. Keep callbacks short and do not call back into any
 * tcp_conn_* API (send, recv, close, or accessors) because the coarse lock is
 * already held and would self-deadlock.
 */
struct tcp_notify {
    void (*on_establish)(struct tcp_conn *c);
    void (*on_disconnect)(struct tcp_conn *c);
    void (*on_window_update)(struct tcp_conn *c, u32 new_window);
    void (*on_data_available)(struct tcp_conn *c);
};

/* Attach event notification hooks to a connection.  Pass NULL to disable.
 * The caller must ensure 'notify' remains valid for the connection's lifetime
 * (typically a static or global struct).  The pointer is stored, not copied.
 */
void tcp_conn_set_notify(struct tcp_conn *conn,
                         const struct tcp_notify *notify);

/* Return a string allocated from 'arn' that represents the connection. */
struct str tcp_conn_format(struct tcp_conn *conn, struct arena *arn);

/* Create a connection to listen for incoming connections. If a segment destined
 * for the given IP address and port arrives, a new connection will be
 * established. Call 'tcp_conn_accept' on the connection returned from this
 * function to access these connections.
 */
struct tcp_conn *tcp_conn_listen(struct ipv4_addr addr,
                                 u16 port,
                                 struct arena tmp);

/* Get a handle to a connection that was listened for by 'listen_conn' (if any).
 */
struct tcp_conn *tcp_conn_accept(struct tcp_conn *listen_conn);

/* Send 'payload' to the other side of the connection 'conn'. The return value
 * indicates the number of bytes that could be transmitted. The
 * 'peer_closed_conn' flag will be updated to indicate whether the peer closed
 * the connection. Once this has happened, you can continue to transmit data,
 * but the peer may be ignoring it, which makes the transmit window fill up. No
 * additional data is transmitted when the transmit window is full which means
 * that this function just returns 0. You are advised to check the
 * 'peer_closed_conn' flag and, if it's set, stop retrying transmission after a
 * while.
 */
struct result_sz tcp_conn_send(struct tcp_conn *conn,
                               struct byte_view payload,
                               bool *peer_closed_conn,
                               struct arena tmp);

/* Store data received on the connection 'conn' into 'buf'. On success, returns
 * the maximum number of bytes available to receive. This means 0 is returned if
 * there is no data. In this case, wait a bit and try again. If there is more
 * data available than the buffer can fit, the total number of bytes available
 * is returned and the buffer is filled to its limit. The 'peer_closed_conn'
 * flag will be updated to indicate whether the peer closed the connection. Once
 * this has happened, you can receive data for as long as you want, but you
 * won't get any more. At that point, call 'tcp_conn_close'.
 */
struct result_sz tcp_conn_recv(struct tcp_conn *conn,
                               struct byte_buf *buf,
                               bool *peer_closed_conn);

/* Close the connection '*conn'. 'conn' will be set to NULL since it's stale
 * now.
 */
struct result tcp_conn_close(struct tcp_conn **conn, struct arena tmp);

struct tcp_stats {
    struct time_ms uptime;
    sz n_connections;   /* Number of active connections. */
    sz sbq_mem;         /* Memory allocated for send buffer queues. */
    sz recv_mem;        /* Memory allocated for receive buffers. */
    sz bytes_tx;        /* Number of bytes ever transmitted. */
    sz bytes_rx;        /* Number of bytes ever received. */
    sz retransmits;     /* Cumulative retransmit events. */
    sz pool_exhaustion; /* Times the connection pool was full (SYN dropped). */
};

struct tcp_stats tcp_stats_get(void);

/* Connection table iteration */

struct tcp_conn_info {
    u64 pkts_sent;
    u64 pkts_recv;
    u64 bytes_sent;
    u64 bytes_recv;
    struct str state_name;
    u32 send_next;
    u32 recv_next;
    u32 cwnd;
    u32 ssthresh;
    u32 retransmits;
    u32 dup_acks;
    u32 ooo_segments;
    u16 host_port;
    u16 peer_port;
    struct ipv4_addr host_addr;
    struct ipv4_addr peer_addr;
};

typedef void (*tcp_conn_iter_cb_t)(struct tcp_conn_info info, void *ctx);

/* Iterate all active connections, calling 'cb' for each one. Serialized by the
 * internal TCP spinlock.
 */
void tcp_for_each_conn(tcp_conn_iter_cb_t cb, void *ctx);

/* Initiate an outbound (active open) TCP connection to the given remote
 * address and port.  Returns a connection handle in the SYN_SENT state.  The
 * caller must poll tcp_conn_is_connected() to detect when the three-way
 * handshake completes.  Returns NULL on failure (no route, pool exhaustion).
 */
struct tcp_conn *tcp_conn_connect(struct ipv4_addr remote_addr,
                                  u16 remote_port,
                                  struct arena tmp);

/* Return true once the connection has reached the ESTABLISHED state. */
bool tcp_conn_is_connected(struct tcp_conn *conn);

/* Return true if the connection was refused or timed out (RESET state).
 * Use together with tcp_conn_is_connected() to distinguish "still connecting"
 * from "connection failed" when polling after tcp_conn_connect().
 */
bool tcp_conn_is_reset(struct tcp_conn *conn);

/* Return true if the connection's receive buffer contains unread data. */
bool tcp_conn_has_data(struct tcp_conn *conn);

/* Return true if 'listen_conn' has at least one accepted connection ready for
 * the user.
 */
bool tcp_conn_has_pending(struct tcp_conn *listen_conn);

#if CONFIG_PMTUD
/* Notify TCP of a PMTU change (ICMP Frag Needed).  Reduces MSS for all
 * connections to dest whose current MSS exceeds the new path MTU.
 */
void tcp_pmtu_update(struct ipv4_addr dest, u16 new_mtu);
#endif

#endif /* MAZU_NET_TCP_H */
