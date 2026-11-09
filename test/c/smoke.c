/*
 * libsmbd's C interface, end to end: a host with one share and
 * one user, an SMB 3.1.1 NEGOTIATE over TCP and over an adopted
 * socket, the activity view, and stop. Run by `zig build test`.
 */
#include <smbd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

#define CHECK(cond)                                              \
    do {                                                         \
        if (!(cond)) {                                           \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n",         \
                    __FILE__, __LINE__, #cond);                  \
            failures++;                                          \
        }                                                        \
    } while (0)

static int list_shares(void *ctx, smbd_shares *out) {
    smbd_share docs = {
        .name = "docs", .path = (const char *)ctx,
        .comment = "perihelion"};
    return smbd_shares_add(out, &docs);
}

static int nt_hash(void *ctx, const char *user,
                   unsigned char hash[16]) {
    (void)ctx;
    if (strcmp(user, "hal") != 0) return 0;
    return smbd_nt_hash("daisy", hash) == SMBD_OK ? 1 : -1;
}

static int logged;

static void log_line(void *ctx, int level, uint64_t conn_id,
                     const char *kind, const char *msg) {
    (void)ctx, (void)level, (void)conn_id, (void)kind, (void)msg;
    logged++;
}

static void put16(unsigned char *p, unsigned v) {
    p[0] = v & 0xff;
    p[1] = v >> 8;
}

static void put32(unsigned char *p, unsigned v) {
    put16(p, v & 0xffff);
    put16(p + 2, v >> 16);
}

/* Sends an SMB 3.1.1 NEGOTIATE with a preauth context on `fd`
   and returns the dialect of the reply (0 on failure). */
static unsigned negotiate(int fd) {
    unsigned char m[4 + 150];
    unsigned char *h = m + 4, *b = h + 64, *ctx = h + 104;
    memset(m, 0, sizeof m);
    m[3] = 150; /* NetBIOS length */
    memcpy(h, "\xfeSMB", 4);
    put16(h + 4, 64);
    put16(h + 14, 1); /* credits requested */
    put16(b, 36);
    put16(b + 2, 1);  /* one dialect */
    put16(b + 4, 1);  /* signing enabled */
    memset(b + 12, 0x42, 16); /* client GUID */
    put32(b + 28, 104); /* context offset */
    put16(b + 32, 1);
    put16(b + 36, 0x0311);
    put16(ctx, 1);  /* preauth integrity */
    put16(ctx + 2, 38);
    put16(ctx + 8, 1);  /* one hash */
    put16(ctx + 10, 32);
    put16(ctx + 12, 1); /* SHA-512 */
    memset(ctx + 14, 0x24, 32);
    if (write(fd, m, sizeof m) != (ssize_t)sizeof m) return 0;

    unsigned char r[1024];
    size_t got = 0;
    while (got < 4 + 64 + 6) {
        ssize_t n = read(fd, r + got, sizeof r - got);
        if (n <= 0) return 0;
        got += (size_t)n;
    }
    unsigned char *rh = r + 4;
    if (memcmp(rh, "\xfeSMB", 4) != 0) return 0;
    if (rh[8] | rh[9] | rh[10] | rh[11]) return 0; /* status */
    return rh[64 + 4] | rh[64 + 5] << 8;
}

int main(void) {
    char dir[4096];
    CHECK(getcwd(dir, sizeof dir) != NULL);

    unsigned char h[16];
    CHECK(smbd_nt_hash("password", h) == SMBD_OK);
    CHECK(h[0] == 0x88 && h[1] == 0x46 && h[15] == 0x6c);
    CHECK(smbd_version()[0] != '\0');
    CHECK(strcmp(smbd_strerror(SMBD_EINVAL),
                 "invalid argument") == 0);

    smbd_host host = {.ctx = dir, .list_shares = list_shares,
                      .nt_hash = nt_hash, .log = log_line};
    smbd_config cfg;
    smbd_config_init(&cfg);
    cfg.server_name = "perihelion";
    CHECK(smbd_new(&host, NULL) == NULL);
    smbd_server *srv = smbd_new(&host, &cfg);
    CHECK(srv != NULL);
    if (!srv) return 1;

    CHECK(smbd_listen(srv, "127.0.0.1", 0) == SMBD_OK);
    CHECK(smbd_listen(srv, "not an address", 0) == SMBD_EINVAL);
    uint16_t port = smbd_port(srv);
    CHECK(port != 0);

    /* A client of the listener. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
    CHECK(negotiate(fd) == 0x0311);

    /* A client the host accepted itself. */
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    CHECK(smbd_adopt_fd(srv, pair[0]) == SMBD_OK);
    CHECK(negotiate(pair[1]) == 0x0311);

    smbd_stats st;
    CHECK(smbd_get_stats(srv, &st) == SMBD_OK);
    CHECK(st.connections_now == 2 && st.connections_total == 2);
    CHECK(st.requests >= 2);
    char *json = smbd_activity_json(srv);
    CHECK(json && strstr(json, "\"PERIHELION\"") != NULL);
    smbd_free_string(json);
    CHECK(smbd_share_changed(srv, "docs", SMBD_KICK_NONE) == 0);
    CHECK(smbd_share_changed(srv, "docs", 7) == SMBD_EINVAL);
    CHECK(smbd_user_changed(srv, "hal") == 0);

    smbd_stop(srv);
    smbd_stop(srv);
    CHECK(smbd_wait(srv) == SMBD_OK);
    char c;
    CHECK(read(fd, &c, 1) == 0); /* dropped */
    CHECK(read(pair[1], &c, 1) == 0);
    CHECK(smbd_get_stats(srv, &st) == SMBD_OK);
    CHECK(st.connections_now == 0);
    CHECK(smbd_listen(srv, "127.0.0.1", 0) == SMBD_ESTOPPED);
    CHECK(smbd_adopt_fd(srv, fd) == SMBD_ESTOPPED);
    smbd_free(srv);
    close(fd);
    close(pair[1]);

    /* A second server after the shared I/O was freed. */
    srv = smbd_new(&host, &cfg);
    CHECK(srv != NULL);
    CHECK(smbd_listen(srv, "127.0.0.1", 0) == SMBD_OK);
    smbd_free(srv);

    (void)logged;
    if (failures) fprintf(stderr, "%d failure(s)\n", failures);
    return failures != 0;
}
