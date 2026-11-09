/*
 * libsmbd: an embeddable SMB 3.1.1 file server (the server inside
 * zsmbd). The host program supplies shares and users through
 * callbacks and receives the log; libsmbd stores nothing.
 *
 * Guide: src/smb/README.md. Before 1.0 this interface may change
 * in any release; check smbd_version().
 *
 * Threads: each client is served on a thread of libsmbd's own.
 * Host callbacks run on those threads, concurrently, so they
 * must be thread-safe, and must not call smbd_stop or smbd_free.
 * Every other function may be called from any thread, except
 * that smbd_listen, smbd_stop, and smbd_free must not race each
 * other on one server.
 *
 * Signals: while any server exists, libsmbd installs do-nothing
 * handlers for SIGIO (used to interrupt blocked threads) and
 * SIGPIPE, and restores the previous ones when the last server
 * is freed.
 *
 * Errors: functions returning int return SMBD_OK (0) or a
 * negative SMBD_E* code; see smbd_strerror.
 */
#ifndef SMBD_H
#define SMBD_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SMBD_OK 0
#define SMBD_ENOMEM (-1)
#define SMBD_EINVAL (-2)
#define SMBD_EADDRINUSE (-3)
#define SMBD_EACCES (-4)
#define SMBD_ESTOPPED (-5)
#define SMBD_EFAIL (-6)

/* Log levels, passed to smbd_host.log. */
#define SMBD_LOG_ERR 0
#define SMBD_LOG_WARN 1
#define SMBD_LOG_INFO 2

/* smbd_share_changed: whom a relaxing change also drops. */
#define SMBD_KICK_NONE 0
/* Trees opened read-only on a share now writable. */
#define SMBD_KICK_WRITABLE 1
/* Anonymous sessions, on a share now open to guests. */
#define SMBD_KICK_GUESTS 2

typedef struct smbd_server smbd_server;
/* Collects the shares a list_shares callback adds. */
typedef struct smbd_shares smbd_shares;

typedef struct smbd_share {
    const char *name;    /* matched case-insensitively */
    const char *path;    /* absolute directory */
    const char *comment; /* may be NULL */
    bool read_only;
    /* Anonymous sessions may connect (only while signing is
       not required, since they can't sign). */
    bool guest_ok;
} smbd_share;

typedef struct smbd_host {
    void *ctx; /* passed to each callback */
    /* Required. Adds every share with smbd_shares_add, then
       returns 0; nonzero fails the client's request. Called on
       each tree connect and share listing, so changes apply to
       the next connection. */
    int (*list_shares)(void *ctx, smbd_shares *out);
    /* Required. For SMB user `user` (case-insensitive), writes
       the NT hash (see smbd_nt_hash) to `hash` and returns 1;
       returns 0 for no such user or no SMB password, negative
       on failure. */
    int (*nt_hash)(void *ctx, const char *user,
                   unsigned char hash[16]);
    /* Optional (NULL drops the log). `conn_id` 0 is the
       server; the strings last only for the call. */
    void (*log)(void *ctx, int level, uint64_t conn_id,
                const char *kind, const char *msg);
} smbd_host;

typedef struct smbd_config {
    const char *server_name; /* required; up to 15 characters */
    const char *workgroup;   /* NULL: "WORKGROUP" */
    bool signing_required;
    bool encrypt; /* every session must encrypt */
} smbd_config;

typedef struct smbd_stats {
    uint64_t connections_now;
    uint64_t connections_total;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t data_read;
    uint64_t data_written;
    uint64_t requests;
    uint64_t logon_failures;
} smbd_stats;

const char *smbd_version(void);
const char *smbd_strerror(int err);

/* Defaults: name "SMBD", "WORKGROUP", signing required, no
   encryption. */
void smbd_config_init(smbd_config *config);

/* MD4 of the UTF-16LE password, for nt_hash callbacks. */
int smbd_nt_hash(const char *password, unsigned char out[16]);

/* From a list_shares callback: copies `share` into `out`. */
int smbd_shares_add(smbd_shares *out, const smbd_share *share);

/* A server that serves nothing until smbd_listen or
   smbd_adopt_fd. `host` and `config` (with its strings) are
   copied. NULL on bad arguments or no memory. */
smbd_server *smbd_new(const smbd_host *host,
                      const smbd_config *config);

/* Replaces the settings; new sessions use them. */
int smbd_set_config(smbd_server *server,
                    const smbd_config *config);

/* Listens on `addr` (NULL: "0.0.0.0"; IPv6 literals work) and
   `port` (0: any; see smbd_port), up to 4 times per server. */
int smbd_listen(smbd_server *server, const char *addr,
                uint16_t port);

/* The port of the latest smbd_listen. */
uint16_t smbd_port(smbd_server *server);

/* Serves one connected TCP socket the host accepted. On
   success libsmbd owns `fd` and closes it; on error the host
   still does. */
int smbd_adopt_fd(smbd_server *server, int fd);

/* Stops listening, drops every client, and returns once their
   threads have finished. Later calls do nothing. */
void smbd_stop(smbd_server *server);

/* Blocks until smbd_stop has finished. */
int smbd_wait(smbd_server *server);

/* Stops the server if needed, then frees it. */
void smbd_free(smbd_server *server);

/* After changing share `name`: drops the clients whose access
   it tightened (and, with a kick, those still on stricter
   rules). Returns how many, or a negative error. */
int smbd_share_changed(smbd_server *server, const char *name,
                       int kick);

/* After changing user `name`: drops their clients if they no
   longer have an NT hash. Returns how many. */
int smbd_user_changed(smbd_server *server, const char *name);

/* Drops one client (IDs are in the activity JSON). */
bool smbd_kick(smbd_server *server, uint64_t conn_id);

int smbd_get_stats(smbd_server *server, smbd_stats *out);

/* Connections, sessions, trees, the last 512 events, and the
   counters, as JSON. Free with smbd_free_string; NULL on no
   memory. */
char *smbd_activity_json(smbd_server *server);
void smbd_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif
