# Reliable delivery and ordering in MUD

This document describes why MUD does not provide reliable, ordered delivery today, what we want to add (without tunnel resegmentation for now), and how it can improve link health detection. **Resegmentation** (TUN MTU larger than wire MTU) is explicitly out of scope here and can be layered on later.

## The challenge

### Current behavior

- Payload traffic uses **UDP**: `mud_send` encrypts one inner buffer into **one** outer datagram. There is **no sequence number** and **no acknowledgment** for tunnel payloads.
- The receiver cannot tell the sender whether a packet arrived. **Loss is invisible** at the MUD layer for payload traffic.
- **Multipath** scheduling sends successive packets on different paths by weighted selection. **UDP does not preserve order** across paths or even on a single path under loss/reordering.
- Control-plane messages carry **aggregate** counters (`tx`/`rx` bytes and totals) used for **statistical** loss and rate estimates. That is **slow** and **approximate** compared to per-packet feedback.

### What we want

1. **Reliable delivery**: The sender retains a copy until the peer confirms receipt (or the packet is abandoned under policy). **Retransmit** when confirmation does not arrive in time.
2. **Ordered delivery to the upper layer**: The peer should hand **inner frames** to the application (e.g. TUN write) **in sequence number order**, using a **reorder buffer** so temporary out-of-order arrivals (multipath, retransmits) do not reorder IP packets seen by the kernel.
3. **Tighter coupling to path health**: Retransmit timeouts and ACK arrival patterns should feed **link up / down or degraded** decisions so poor paths are detected **faster** than aggregate control-plane stats alone.

### Non-goals (for this phase)

- **Resegmentation / fragmentation**: Inner frames are still assumed to fit in a single MUD datagram after encryption (same as today). TUN MTU remains driven by `mud_get_mtu()` until a separate fragmentation design is added.
- Replacing **TCP** or **QUIC** reliability for traffic that already uses those protocols inside the tunnel; the goal is **MUD-layer** semantics for whatever IP the tunnel carries.

## Solution outline

### Sequence space and framing

- Introduce a **unidirectional sequence number** per traffic direction (or a single space per association with clear rules), embedded in the **authenticated** payload (inside AEAD) so it cannot be forged.
- Each **logical packet** (one inner datagram) gets one **sequence number**. Retransmits reuse the **same** sequence number so the receiver can **deduplicate**.

### Acknowledgments

- The peer sends **ACKs** for received sequence numbers. Design options:
  - **Cumulative ACK** (simpler): “All sequences up to *N* received.”
  - **Bitmap / range ACK** (better on lossy links): Acknowledge non-contiguous reception for selective repeat.
- ACKs may be **piggybacked** on reverse payload traffic and/or sent as **small standalone** packets when there is nothing to piggyback (or periodically on the beat).

### Send buffer and retransmit

- **Unacked packets** stay in a **send buffer** keyed by sequence number, with metadata (first send time, path used if relevant, retry count).
- **Retransmit timeout**: Use **`path->conf.beat`** (scaled to the same time base as the rest of MUD) as the **initial RTO** per packet or per path. If no ACK is seen before **beat × k** (small integer *k*, e.g. 1–2) or a capped maximum, **retransmit** the same sequence number. Optionally **increase** backoff on repeated loss (while still anchored to beat).
- **Buffer bounds**: Cap queued bytes and/or time so memory and latency stay bounded; policy when full (drop oldest, block `mud_send`, or signal error) must be explicit.

### Receive reorder buffer

- On decrypt, accept only **in-window** sequence numbers (replay protection + reorder window).
- Hold packets in a **structure keyed by seq** until **contiguous** delivery from `next_read_seq` is possible; deliver to the upper layer in order.
- **Hole timer**: If the next expected sequence is missing longer than a **multiple of beat**, treat as loss for **reliability** (sender will retransmit) and optionally for **link quality** (see below).

### Interaction with multipath

- Retransmits may use the **same path** or a **different** path (policy). Same-seq retransmits must still **dedupe** at the receiver.
- Scheduling weights can **prefer** paths with lower recent **loss or RTT** derived from ACK behavior, not only from aggregate `mud_msg` counters.

### Feedback into link up / down / degraded

Reliability provides **timely signals** that aggregate stats lack:

- **ACK latency** vs **beat** (and vs **RTT** from control messages): persistent delays suggest congestion or asymmetric routing.
- **Retransmit rate** per path: high retransmit fraction ⇒ **degrade** or **avoid** that path even before `tx.loss` from counters catches up.
- **Missing ACKs** for several **beat** intervals: align with or **tighten** existing “missed beats” / **DEGRADED** logic so **path status** reacts to **payload-plane** failure, not only control-plane heartbeats.

Existing **`heartbeat_miss_max`**, **`loss_limit`**, and **pref** logic can be **supplemented** (not necessarily replaced) with thresholds driven by **ACK/retransmit** metrics so “link down” or “not usable for traffic” tracks **actual** delivery experience.

## Implementation checklist

Use this as the working task list (see also project todos).

1. **Spec wire format** — Sequence width, ACK format (cumulative vs selective), flags for “ACK-only” packets, version/interop field if needed.
2. **Crypto** — Include seq in AEAD AAD or plaintext as required by the cipher API; define **replay window** and drop rules.
3. **Sender** — Send buffer, assign seq on `mud_send`, remove on ACK, RTO = **f(beat)** with documented multiplier and max retries.
4. **Retransmit** — Timer or scan driven by `mud_update`; same-seq resend; multipath policy for retx.
5. **Receiver** — ACK generation after successful decrypt and duplicate detection; optional piggyback.
6. **Reorder buffer** — In-order delivery to caller; window size; hole handling.
7. **API** — `mud_recv` / `mud_send` behavior under backpressure; errors when buffer full.
8. **Glorytun** — Integrate if buffer delivery is pull-based or if sizes change; TUN loop unchanged if API stays stream-like.
9. **Link quality** — Feed retransmit/ACK stats into `mud_path_update` or parallel hooks for **DEGRADED** / **RUNNING** transitions.
10. **Tests** — Unit tests for reorder/dedup; loss/reorder simulation; fuzz framing.

## References in tree

- Payload path: `mud_encrypt` / `mud_decrypt`, `mud_send`, `mud_recv` in `mud.c`.
- Path health today: `mud_path_update`, `mud_path_track`, `mud_recv_msg`, `mud_update_rl` in `mud.c`.
- TUN MTU: `mud_get_mtu`, `gt_setup_mtu` in `bind.c` (no change required for reliability-only work).

## Implementation status (in-tree)

### Wire format (reliable payload packets)

Outer UDP layout:

1. **6 bytes** — timestamp with `MUD_REL_BIT` (0x4) set in the low bits (not `MUD_MSG`).
2. **8 bytes** — sender sequence number (little-endian).
3. **8 bytes** — cumulative ACK: next sequence number the sender expects from the peer (little-endian).
4. **Ciphertext** — AEAD over the inner IP payload; **additional authenticated data** is the 16 bytes at offsets 6–21 (`seq || ack`). Nonce is the first 6 bytes (timestamp), matching legacy MUD.

Legacy packets (no `MUD_REL_BIT`) still use the old `MUD_TIME_SIZE + MAC + payload` layout when `mud_set` disables reliable mode.

### Automated tests (repeatable)

From `mud/`:

```bash
make test
```

This builds **`t_reliable_echo`** with **`-DMUD_TEST`**, runs:

1. **Loopback echo** — forked server/client on `127.0.0.1:20000` / `:20001`, verifies the payload matches.
2. **Retransmit** — same with **`MUD_TEST_DROP_INCOMING=1`**, which discards the first raw UDP datagram on receive (test hook in `mud.c`) so the client must retransmit.

CI or scripts can run `make -C mud test`; exit status is non-zero on failure.

### API

- `struct mud_conf` includes **`reliable`**: `0` = leave unchanged on `mud_set`; `1` = disable reliable mode; `2` or greater = enable. After `mud_set`, the struct echoes `1` (off) or `2` (on).
- `mud_create` enables reliable mode by default, sets the socket **non-blocking**, and initializes sequence / reorder state.
- **RTO**: `beat × 2^min(retransmits,3)` using the minimum `beat` among active paths (fallback 100 ms).
- **Path health**: per-path `rel_retx` counts retransmissions; if `≥ MUD_REL_RETX_DEGRADE` (8), the path is marked **LOSSY** in `mud_path_update`.
