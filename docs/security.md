# Security

Mazu transmits all traffic, including web-terminal keystrokes and output,
over plaintext HTTP with no transport security. It is not safe to expose
the kernel directly on an untrusted LAN or the public internet.

The recommended approach is to place Mazu behind a TLS-terminating reverse
proxy on the same host or inside the same trusted network segment.
Popular options include Nginx (`proxy_pass http://192.168.100.2`) and
Caddy. A WireGuard tunnel is also appropriate when the host itself is
remote.

## Deployment constraints

1. TLS. Use a reverse proxy (Nginx, Caddy) or a WireGuard tunnel to
   encrypt traffic in transit. TLS alone does not authenticate users.

2. Authentication. Add HTTP basic auth at the proxy layer (or equivalent
   network ACLs) to prevent unauthorized access to the web terminal. The
   kernel itself has no user authentication beyond session tokens for the
   terminal API.

3. Network isolation. The kernel listens on every address it has an IP
   for. Restrict access at the firewall or via the TAP interface to
   limit exposure.

Adding a TLS library (e.g., BearSSL, ~45 KB) directly to the kernel
is an option if standalone deployment is required, but conflicts
with the compact-kernel goal.

## Syscall authorization

The kernel enforces a syscall security policy at the kernel-user
boundary. Each syscall passes through a 3-gate authorization check:
valid syscall number (`ENOSYS`), process context requirement (`EPERM`),
and per-process `syscall_allow` bitmask whitelist (`EACCES`). Denied
syscalls are logged to the kernel log ring buffer. Security counters
are exposed via `/api/stats`.

## Memory safety hardenings

- W^X enforcement: user-space pages cannot be simultaneously writable
  and executable. Code pages are loaded as R+W, then transitioned to
  R+X after the binary data is copied. ELF binaries requesting W+X
  segments are rejected at load time.
- User-pointer sanitization: `copy_from_user` / `copy_to_user`
  (`kernel/proc/uaccess.c`) validate every transfer in four layers
  before toggling `sstatus.SUM` and issuing the actual copy:
  1. Range and overflow: pointer plus length must not wrap and must
     lie inside `[USER_CODE_BASE, USER_STACK_TOP)`.
  2. VMA permission: when the process has registered VMAs
     (`n_vmas > 0`), `proc_vma_check_access` is called with
     `VMA_PERM_READ` for `copy_from_user` and `VMA_PERM_WRITE` for
     `copy_to_user`, so the requested direction is enforced against
     the VMA's recorded permissions.
  3. Page-table walk: `paging_user_range_accessible` (read direction)
     or `paging_user_range_writable` (write direction) verifies
     `PTE_U` and the matching read/write bit on every page in the
     range. A per-CPU single-page cache keyed on a global
     paging-validation generation skips the walk for repeated hits to
     the same page.
  4. SUM-gated copy with fault recovery: the actual load/store path
     enables `SUM`, and the trap handler unwinds cleanly into an
     `EFAULT` return if a page fault is taken inside the window.
- VMA tracking: a per-process virtual memory area list records code,
  stack, and data regions with permissions. Accesses outside any
  registered VMA return `EFAULT`. Processes with no registered VMAs
  (`n_vmas == 0`, e.g., kernel tasks) skip layer 2 and fall back to
  range plus page-table validation only.
- Stack-protector: GCC `-fstack-protector-strong` (when
  `CONFIG_STACK_PROTECTOR=y`) places canary values between local
  variables and return addresses. The canary is initialized early in
  boot from entropy-mixed `rdtime()` samples. Corruption triggers a
  hard halt.
- Guard pages: the bottom 4 KiB of each kernel task stack is unmapped.
  Stack overflow causes a page fault instead of silent memory
  corruption. User-space stacks do not currently have an explicit guard
  page.
- Magic number validation (debug builds): `struct proc` and `struct
  sched_task` carry magic numbers validated on access. Freed process and
  task objects are poisoned with `0xDEADDEAD` for use-after-free
  detection. This coverage is scoped to proc/task structures, not all
  kernel objects.

## Programming style defenses

The C programming style provides additional defense through
length-prefixed strings (`struct str`) that eliminate null-termination
bugs, and separate types for read-only, read-write, and appendable
buffers that enforce mutability constraints at the type level. No uses
of `strlen`, `strcpy`, `sprintf`, or other unbounded C string functions
exist in the kernel or user code.
