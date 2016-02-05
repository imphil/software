#include "daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct terminal {
    int socket_listen;
    int socket;
    char *path;
    pid_t child;
};

static int nxt_term_id = 0;

int terminal_open(struct terminal **term) {
    struct terminal *t = malloc(sizeof(struct terminal));
    *term = t;

    char name[128];
    snprintf(name, 128, "/tmp/osd-%d-term-%d", getpid(), nxt_term_id++);

    t->path = strdup(name);

    if ((t->socket_listen = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un local, remote;

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, t->path);
    unlink(local.sun_path);
    int len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(t->socket_listen, (struct sockaddr *)&local, len) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(t->socket_listen, 5) == -1) {
        perror("listen");
        exit(1);
    }

    if ((t->child = fork()) == 0) {
        char command[256];
        snprintf(command, 256, "xterm -title test -e bash -l -c 'osd_term %s'", name);
        int rv = system(command);
        exit(rv);
    }

    unsigned int s = sizeof(remote);
    if ((t->socket = accept(t->socket_listen, (struct sockaddr *)&remote, &s)) == -1) {
        perror("accept");
        exit(1);
    }

    return 0;
}

void terminal_ingress(struct osd_context *ctx, void* mod_arg,
                      uint16_t *packet, size_t len) {
    struct terminal *term = (struct terminal *) mod_arg;

    if (len == 3) {
        uint8_t c = packet[2] & 0xff;
        int rv = write(term->socket, &c, 1);
        (void) rv;
    }
}
