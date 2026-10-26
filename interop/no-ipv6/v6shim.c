/*
 * LD_PRELOAD shim that runs IPv6-only server binaries on a kernel without IPv6.
 *
 * Some sandboxes (CI containers, Firecracker VMs) boot a kernel with IPv6 compiled
 * out: socket(AF_INET6, ...) fails with EAFNOSUPPORT, so most quic-interop-runner
 * servers die binding "[::]:443". This shim hands them an AF_INET socket instead and
 * translates at the API boundary: IPv4 addresses travel as v4-mapped IPv6 addresses
 * (::ffff:a.b.c.d), IPV6_* socket options become their IP_* twins, and the
 * IPV6_PKTINFO / IPV6_TCLASS / IPV6_HOPLIMIT control messages are rewritten in
 * both directions. Real IPv6 destinations fail with ENETUNREACH.
 *
 * Only sockets the shim created are touched; everything else passes through.
 *
 * Build: patch-runner.sh compiles it. It needs nothing newer than glibc 2.14, so one
 * .so loads into every glibc the runner images ship. V6SHIM_DEBUG=1 traces failures.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

static int debug_on = -1;
#define DBG(...)                                                              \
    do {                                                                      \
        if (debug_on < 0) debug_on = getenv("V6SHIM_DEBUG") != NULL;          \
        if (debug_on) fprintf(stderr, "[v6shim] " __VA_ARGS__);               \
    } while (0)

#define MAX_FD 65536
static volatile unsigned char fake6[MAX_FD];

static int is_fake(int fd) { return fd >= 0 && fd < MAX_FD && fake6[fd]; }
static void set_fake(int fd, int v) {
    if (fd >= 0 && fd < MAX_FD) fake6[fd] = (unsigned char)v;
}

/*
 * The real calls go straight to the kernel. dlsym(RTLD_NEXT) would be the usual way,
 * but it takes the loader lock, and msquic's lttng thread calls socket() while the
 * main thread holds that lock in dlopen: a deadlock before main() runs.
 */
#define real_socket(d, t, p) ((int)syscall(SYS_socket, d, t, p))
#define real_bind(f, a, l) ((int)syscall(SYS_bind, f, a, l))
#define real_connect(f, a, l) ((int)syscall(SYS_connect, f, a, l))
#define real_sendto(f, b, n, fl, a, l) ((ssize_t)syscall(SYS_sendto, f, b, n, fl, a, l))
#define real_sendmsg(f, m, fl) ((ssize_t)syscall(SYS_sendmsg, f, m, fl))
#define real_sendmmsg(f, v, n, fl) ((int)syscall(SYS_sendmmsg, f, v, n, fl))
#define real_recvfrom(f, b, n, fl, a, l) ((ssize_t)syscall(SYS_recvfrom, f, b, n, fl, a, l))
#define real_recvmsg(f, m, fl) ((ssize_t)syscall(SYS_recvmsg, f, m, fl))
#define real_recvmmsg(f, v, n, fl, t) ((int)syscall(SYS_recvmmsg, f, v, n, fl, t))
#define real_getsockname(f, a, l) ((int)syscall(SYS_getsockname, f, a, l))
#define real_getpeername(f, a, l) ((int)syscall(SYS_getpeername, f, a, l))
#define real_setsockopt(f, lv, o, v, l) ((int)syscall(SYS_setsockopt, f, lv, o, v, l))
#define real_getsockopt(f, lv, o, v, l) ((int)syscall(SYS_getsockopt, f, lv, o, v, l))
#define real_accept4(f, a, l, fl) ((int)syscall(SYS_accept4, f, a, l, fl))
#define real_accept(f, a, l) real_accept4(f, a, l, 0)
#define real_close(f) ((int)syscall(SYS_close, f))
#define real_dup(f) ((int)syscall(SYS_dup, f))
#define real_dup3(f, g, fl) ((int)syscall(SYS_dup3, f, g, fl))
#define real_fcntl(f, c, a) ((int)syscall(SYS_fcntl, f, c, a))

/* in6 -> in. Returns 0, or -1 with errno set for an address IPv4 can't carry. */
static int to4(const struct sockaddr *sa, socklen_t len, struct sockaddr_in *out, int bindErr) {
    if (!sa || len < sizeof(struct sockaddr_in6) || sa->sa_family != AF_INET6) return 1;
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = s6->sin6_port;
    const uint8_t *a = s6->sin6_addr.s6_addr;
    if (IN6_IS_ADDR_UNSPECIFIED(&s6->sin6_addr)) {
        out->sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
        memcpy(&out->sin_addr, a + 12, 4);
    } else if (IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr)) {
        out->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        errno = bindErr ? EADDRNOTAVAIL : ENETUNREACH;
        return -1;
    }
    return 0;
}

static void mapped(struct in6_addr *dst, const struct in_addr *src) {
    memset(dst, 0, sizeof(*dst));
    if (src->s_addr == htonl(INADDR_ANY)) return;
    dst->s6_addr[10] = 0xff;
    dst->s6_addr[11] = 0xff;
    memcpy(dst->s6_addr + 12, src, 4);
}

/* in -> in6, written into the caller's buffer the way the kernel would. */
static void to6(struct sockaddr *dst, socklen_t *len, const struct sockaddr_in *src) {
    if (!dst || !len) return;
    struct sockaddr_in6 s6;
    memset(&s6, 0, sizeof(s6));
    s6.sin6_family = AF_INET6;
    s6.sin6_port = src->sin_port;
    mapped(&s6.sin6_addr, &src->sin_addr);
    if (src->sin_addr.s_addr == htonl(INADDR_ANY)) memset(&s6.sin6_addr, 0, sizeof(s6.sin6_addr));
    socklen_t n = *len < sizeof(s6) ? *len : sizeof(s6);
    memcpy(dst, &s6, n);
    *len = sizeof(s6);
}

int socket(int domain, int type, int protocol) {
    int fd = real_socket(domain, type, protocol);
    if (fd < 0 && domain == AF_INET6 && errno == EAFNOSUPPORT) {
        fd = real_socket(AF_INET, type, protocol);
        if (fd >= 0) set_fake(fd, 1);
    } else if (fd >= 0) {
        set_fake(fd, 0);
    }
    return fd;
}

int close(int fd) {
    set_fake(fd, 0);
    return real_close(fd);
}

int dup(int fd) {
    int r = real_dup(fd);
    if (r >= 0) set_fake(r, is_fake(fd));
    return r;
}

int dup2(int fd, int fd2) {
    int r = fd == fd2 ? real_fcntl(fd, F_GETFD, 0) < 0 ? -1 : fd : real_dup3(fd, fd2, 0);
    if (r >= 0) set_fake(r, is_fake(fd));
    return r;
}

int dup3(int fd, int fd2, int flags) {
    int r = real_dup3(fd, fd2, flags);
    if (r >= 0) set_fake(r, is_fake(fd));
    return r;
}

/* Rust's try_clone() and friends duplicate through fcntl. */
int fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);
    int r = real_fcntl(fd, cmd, arg);
    if (r >= 0 && (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)) set_fake(r, is_fake(fd));
    return r;
}

int fcntl64(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);
    int r = real_fcntl(fd, cmd, arg);
    if (r >= 0 && (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)) set_fake(r, is_fake(fd));
    return r;
}

/* Ports a shimmed socket holds on the IPv4 wildcard address. */
static volatile unsigned char wild_port[65536];

int bind(int fd, const struct sockaddr *sa, socklen_t len) {
    if (!is_fake(fd)) {
        int r = real_bind(fd, sa, len);
        /* Servers that bind both [::]:p and 0.0.0.0:p: the shimmed socket already serves p. */
        if (r < 0 && errno == EADDRINUSE && sa && sa->sa_family == AF_INET &&
            ((const struct sockaddr_in *)sa)->sin_addr.s_addr == htonl(INADDR_ANY) &&
            wild_port[ntohs(((const struct sockaddr_in *)sa)->sin_port)])
            return 0;
        return r;
    }
    struct sockaddr_in s4;
    int c = to4(sa, len, &s4, 1);
    if (c < 0) return -1;
    if (c > 0) return real_bind(fd, sa, len);
    int r = real_bind(fd, (struct sockaddr *)&s4, sizeof(s4));
    if (s4.sin_addr.s_addr == htonl(INADDR_ANY)) {
        /* Servers that bind both 0.0.0.0:p and [::]:p: the IPv4 socket already serves p. */
        if (r < 0 && errno == EADDRINUSE) return 0;
        if (r == 0) wild_port[ntohs(s4.sin_port)] = 1;
    }
    return r;
}

int connect(int fd, const struct sockaddr *sa, socklen_t len) {
    if (!is_fake(fd)) return real_connect(fd, sa, len);
    struct sockaddr_in s4;
    int c = to4(sa, len, &s4, 0);
    if (c < 0) return -1;
    if (c > 0) return real_connect(fd, sa, len);
    return real_connect(fd, (struct sockaddr *)&s4, sizeof(s4));
}

ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *sa, socklen_t len) {
    if (!is_fake(fd) || !sa) return real_sendto(fd, buf, n, flags, sa, len);
    struct sockaddr_in s4;
    int c = to4(sa, len, &s4, 0);
    if (c < 0) return -1;
    if (c > 0) return real_sendto(fd, buf, n, flags, sa, len);
    return real_sendto(fd, buf, n, flags, (struct sockaddr *)&s4, sizeof(s4));
}

#define CTRL_MAX 4096

/* Rewrite outgoing IPv6 control messages into IPv4 ones. Returns the new length. */
static size_t ctrl_to4(const struct msghdr *m, char *out) {
    size_t used = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR((struct msghdr *)m); c; c = CMSG_NXTHDR((struct msghdr *)m, c)) {
        char data[256];
        size_t dlen = c->cmsg_len - CMSG_LEN(0);
        int level = c->cmsg_level, type = c->cmsg_type;
        if (level == IPPROTO_IPV6 && type == IPV6_PKTINFO && dlen >= sizeof(struct in6_pktinfo)) {
            struct in6_pktinfo p6;
            memcpy(&p6, CMSG_DATA(c), sizeof(p6));
            struct in_pktinfo p4;
            memset(&p4, 0, sizeof(p4));
            p4.ipi_ifindex = (int)p6.ipi6_ifindex;
            if (IN6_IS_ADDR_V4MAPPED(&p6.ipi6_addr)) memcpy(&p4.ipi_spec_dst, p6.ipi6_addr.s6_addr + 12, 4);
            level = IPPROTO_IP;
            type = IP_PKTINFO;
            dlen = sizeof(p4);
            memcpy(data, &p4, dlen);
        } else if (level == IPPROTO_IPV6 && (type == IPV6_TCLASS || type == IPV6_HOPLIMIT) && dlen >= sizeof(int)) {
            type = type == IPV6_TCLASS ? IP_TOS : IP_TTL;
            level = IPPROTO_IP;
            dlen = sizeof(int);
            memcpy(data, CMSG_DATA(c), dlen);
        } else if (level == IPPROTO_IPV6) {
            continue; /* IPV6_DONTFRAG and friends: no per-packet IPv4 twin */
        } else {
            if (dlen > sizeof(data)) continue;
            memcpy(data, CMSG_DATA(c), dlen);
        }
        if (used + CMSG_SPACE(dlen) > CTRL_MAX) break;
        struct cmsghdr *o = (struct cmsghdr *)(out + used);
        o->cmsg_level = level;
        o->cmsg_type = type;
        o->cmsg_len = CMSG_LEN(dlen);
        memcpy(CMSG_DATA(o), data, dlen);
        used += CMSG_SPACE(dlen);
    }
    return used;
}

/* Rewrite incoming IPv4 control messages into the IPv6 ones the caller asked for. */
static void ctrl_to6(struct msghdr *m, const char *in, size_t inlen) {
    size_t cap = m->msg_controllen;
    char *dst = m->msg_control;
    size_t used = 0;
    struct msghdr src;
    memset(&src, 0, sizeof(src));
    src.msg_control = (void *)in;
    src.msg_controllen = inlen;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&src); c; c = CMSG_NXTHDR(&src, c)) {
        char data[256];
        size_t dlen = c->cmsg_len - CMSG_LEN(0);
        int level = c->cmsg_level, type = c->cmsg_type;
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO && dlen >= sizeof(struct in_pktinfo)) {
            struct in_pktinfo p4;
            memcpy(&p4, CMSG_DATA(c), sizeof(p4));
            struct in6_pktinfo p6;
            memset(&p6, 0, sizeof(p6));
            mapped(&p6.ipi6_addr, &p4.ipi_addr);
            p6.ipi6_ifindex = (unsigned)p4.ipi_ifindex;
            level = IPPROTO_IPV6;
            type = IPV6_PKTINFO;
            dlen = sizeof(p6);
            memcpy(data, &p6, dlen);
        } else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TOS && dlen >= 1) {
            int v = *(unsigned char *)CMSG_DATA(c);
            level = IPPROTO_IPV6;
            type = IPV6_TCLASS;
            dlen = sizeof(int);
            memcpy(data, &v, dlen);
        } else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL && dlen >= sizeof(int)) {
            level = IPPROTO_IPV6;
            type = IPV6_HOPLIMIT;
            dlen = sizeof(int);
            memcpy(data, CMSG_DATA(c), dlen);
        } else {
            if (dlen > sizeof(data)) continue;
            memcpy(data, CMSG_DATA(c), dlen);
        }
        if (used + CMSG_SPACE(dlen) > cap) {
            m->msg_flags |= MSG_CTRUNC;
            break;
        }
        struct cmsghdr *o = (struct cmsghdr *)(dst + used);
        o->cmsg_level = level;
        o->cmsg_type = type;
        o->cmsg_len = CMSG_LEN(dlen);
        memcpy(CMSG_DATA(o), data, dlen);
        used += CMSG_SPACE(dlen);
    }
    m->msg_controllen = used;
}

/* Prepares an IPv4 copy of an outgoing msghdr. Returns -1 (errno set) to fail the send. */
static int prep_send(const struct msghdr *m, struct msghdr *o, struct sockaddr_in *s4, char *ctrl) {
    *o = *m;
    if (m->msg_name) {
        int c = to4(m->msg_name, m->msg_namelen, s4, 0);
        if (c < 0) return -1;
        if (c == 0) {
            o->msg_name = s4;
            o->msg_namelen = sizeof(*s4);
        }
    }
    if (m->msg_control && m->msg_controllen) {
        o->msg_controllen = ctrl_to4(m, ctrl);
        o->msg_control = o->msg_controllen ? ctrl : NULL;
    }
    return 0;
}

ssize_t sendmsg(int fd, const struct msghdr *m, int flags) {
    if (!is_fake(fd)) return real_sendmsg(fd, m, flags);
    struct msghdr o;
    struct sockaddr_in s4;
    char ctrl[CTRL_MAX] __attribute__((aligned(8)));
    if (prep_send(m, &o, &s4, ctrl) < 0) return -1;
    return real_sendmsg(fd, &o, flags);
}

#define MMSG_MAX 64

int sendmmsg(int fd, struct mmsghdr *v, unsigned int n, int flags) {
    if (!is_fake(fd)) return real_sendmmsg(fd, v, n, flags);
    if (n > MMSG_MAX) n = MMSG_MAX;
    /* Heap, not TLS: static TLS comes out of every thread's stack, and some servers
     * run small-stack threads. */
    struct send_slot {
        struct sockaddr_in s4;
        char ctrl[CTRL_MAX] __attribute__((aligned(8)));
    } *slot = malloc(sizeof(*slot) * n);
    struct mmsghdr *o = malloc(sizeof(*o) * n);
    if (!slot || !o) {
        free(slot);
        free(o);
        errno = ENOMEM;
        return -1;
    }
    for (unsigned i = 0; i < n; i++) {
        o[i].msg_len = 0;
        if (prep_send(&v[i].msg_hdr, &o[i].msg_hdr, &slot[i].s4, slot[i].ctrl) < 0) {
            if (i == 0) {
                free(slot);
                free(o);
                return -1;
            }
            n = i;
            break;
        }
    }
    int r = real_sendmmsg(fd, o, n, flags);
    int e = errno;
    if (r < 0) {
        DBG("sendmmsg fd=%d n=%u err=%d fam=%d namelen=%u ctrllen=%zu\n", fd, n, e,
            v[0].msg_hdr.msg_name ? ((struct sockaddr *)v[0].msg_hdr.msg_name)->sa_family : -1,
            v[0].msg_hdr.msg_namelen, v[0].msg_hdr.msg_controllen);
    }
    for (int i = 0; i < r; i++) v[i].msg_len = o[i].msg_len;
    free(slot);
    free(o);
    errno = e;
    return r;
}

ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *sa, socklen_t *len) {
    if (!is_fake(fd) || !sa || !len) return real_recvfrom(fd, buf, n, flags, sa, len);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    ssize_t r = real_recvfrom(fd, buf, n, flags, (struct sockaddr *)&ss, &sl);
    if (r >= 0) {
        if (ss.ss_family == AF_INET) {
            to6(sa, len, (struct sockaddr_in *)&ss);
        } else {
            socklen_t c = *len < sl ? *len : sl;
            memcpy(sa, &ss, c);
            *len = sl;
        }
    }
    return r;
}

/* Swaps in IPv4-sized name/control buffers for one receive, then converts back. */
struct recv_ctx {
    struct sockaddr_storage ss;
    char ctrl[CTRL_MAX] __attribute__((aligned(8)));
    void *name;
    socklen_t namelen;
    void *control;
    size_t controllen;
};

static void prep_recv(struct msghdr *m, struct recv_ctx *x) {
    x->name = m->msg_name;
    x->namelen = m->msg_namelen;
    x->control = m->msg_control;
    x->controllen = m->msg_controllen;
    if (m->msg_name) {
        m->msg_name = &x->ss;
        m->msg_namelen = sizeof(x->ss);
    }
    if (m->msg_control) {
        m->msg_control = x->ctrl;
        m->msg_controllen = sizeof(x->ctrl);
    }
}

static void finish_recv(struct msghdr *m, struct recv_ctx *x, int ok) {
    size_t gotctrl = m->msg_controllen;
    socklen_t gotname = m->msg_namelen;
    m->msg_name = x->name;
    m->msg_namelen = x->namelen;
    m->msg_control = x->control;
    m->msg_controllen = x->controllen;
    if (!ok) return;
    if (x->name) {
        if (x->ss.ss_family == AF_INET) {
            to6(m->msg_name, &m->msg_namelen, (struct sockaddr_in *)&x->ss);
        } else {
            socklen_t c = x->namelen < gotname ? x->namelen : gotname;
            memcpy(m->msg_name, &x->ss, c);
            m->msg_namelen = gotname;
        }
    }
    if (x->control) ctrl_to6(m, x->ctrl, gotctrl);
}

ssize_t recvmsg(int fd, struct msghdr *m, int flags) {
    if (!is_fake(fd)) return real_recvmsg(fd, m, flags);
    struct recv_ctx x;
    prep_recv(m, &x);
    ssize_t r = real_recvmsg(fd, m, flags);
    finish_recv(m, &x, r >= 0);
    return r;
}

int recvmmsg(int fd, struct mmsghdr *v, unsigned int n, int flags, struct timespec *t) {
    if (!is_fake(fd)) return real_recvmmsg(fd, v, n, flags, t);
    if (n > MMSG_MAX) n = MMSG_MAX;
    struct recv_ctx *x = malloc(sizeof(*x) * n);
    if (!x) {
        errno = ENOMEM;
        return -1;
    }
    for (unsigned i = 0; i < n; i++) prep_recv(&v[i].msg_hdr, &x[i]);
    int r = real_recvmmsg(fd, v, n, flags, t);
    int e = errno;
    for (unsigned i = 0; i < n; i++) finish_recv(&v[i].msg_hdr, &x[i], r > 0 && (int)i < r);
    free(x);
    errno = e;
    return r;
}

static int sockname(int fd, struct sockaddr *sa, socklen_t *len, int peer) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int r = peer ? real_getpeername(fd, (struct sockaddr *)&ss, &sl) : real_getsockname(fd, (struct sockaddr *)&ss, &sl);
    if (r == 0 && ss.ss_family == AF_INET) {
        to6(sa, len, (struct sockaddr_in *)&ss);
    } else if (r == 0 && sa && len) {
        socklen_t c = *len < sl ? *len : sl;
        memcpy(sa, &ss, c);
        *len = sl;
    }
    return r;
}

int getsockname(int fd, struct sockaddr *sa, socklen_t *len) {
    if (!is_fake(fd)) return real_getsockname(fd, sa, len);
    return sockname(fd, sa, len, 0);
}

int getpeername(int fd, struct sockaddr *sa, socklen_t *len) {
    if (!is_fake(fd)) return real_getpeername(fd, sa, len);
    return sockname(fd, sa, len, 1);
}

static int accept_common(int fd, struct sockaddr *sa, socklen_t *len, int flags, int four) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int r = four ? real_accept4(fd, (struct sockaddr *)&ss, &sl, flags) : real_accept(fd, (struct sockaddr *)&ss, &sl);
    if (r >= 0) {
        set_fake(r, 1);
        if (sa && len) {
            if (ss.ss_family == AF_INET) {
                to6(sa, len, (struct sockaddr_in *)&ss);
            } else {
                socklen_t c = *len < sl ? *len : sl;
                memcpy(sa, &ss, c);
                *len = sl;
            }
        }
    }
    return r;
}

int accept(int fd, struct sockaddr *sa, socklen_t *len) {
    if (!is_fake(fd)) return real_accept(fd, sa, len);
    return accept_common(fd, sa, len, 0, 0);
}

int accept4(int fd, struct sockaddr *sa, socklen_t *len, int flags) {
    if (!is_fake(fd)) return real_accept4(fd, sa, len, flags);
    return accept_common(fd, sa, len, flags, 1);
}

/* IPV6_* option -> IP_* option; 0 when the option is accepted and ignored. */
static int map_opt(int opt) {
    switch (opt) {
    case IPV6_RECVPKTINFO: return IP_PKTINFO;
    case IPV6_RECVTCLASS: return IP_RECVTOS;
    case IPV6_TCLASS: return IP_TOS;
    case IPV6_MTU_DISCOVER: return IP_MTU_DISCOVER;
    case IPV6_RECVERR: return IP_RECVERR;
    case IPV6_UNICAST_HOPS: return IP_TTL;
    case IPV6_RECVHOPLIMIT: return IP_RECVTTL;
    case IPV6_MTU: return IP_MTU;
    default: return 0;
    }
}

int setsockopt(int fd, int level, int opt, const void *val, socklen_t len) {
    if (!is_fake(fd) || level != IPPROTO_IPV6) return real_setsockopt(fd, level, opt, val, len);
    if (opt == IPV6_DONTFRAG) {
        int on = val && len >= (socklen_t)sizeof(int) ? *(const int *)val : 0;
        int pmtu = on ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
        return real_setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
    }
    int m = map_opt(opt);
    if (!m) return 0;
    if (m == IP_MTU) return 0;
    int r = real_setsockopt(fd, IPPROTO_IP, m, val, len);
    return r < 0 ? 0 : r; /* best effort: never fail a server over an option */
}

int getsockopt(int fd, int level, int opt, void *val, socklen_t *len) {
    if (!is_fake(fd)) return real_getsockopt(fd, level, opt, val, len);
    if (level == SOL_SOCKET && opt == SO_DOMAIN && val && len && *len >= (socklen_t)sizeof(int)) {
        *(int *)val = AF_INET6;
        *len = sizeof(int);
        return 0;
    }
    if (level != IPPROTO_IPV6) return real_getsockopt(fd, level, opt, val, len);
    if (opt == IPV6_V6ONLY && val && len && *len >= (socklen_t)sizeof(int)) {
        *(int *)val = 0;
        *len = sizeof(int);
        return 0;
    }
    int m = map_opt(opt);
    if (!m) {
        errno = ENOPROTOOPT;
        return -1;
    }
    return real_getsockopt(fd, IPPROTO_IP, m, val, len);
}
