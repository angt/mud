/*
 * Automated integration test: reliable MUD delivery over loopback UDP.
 * Build: make t_reliable_echo  (requires -DMUD_TEST in mud for drop test)
 */
#include "mud.c"
#include "aegis256/aegis256.c"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char payload[] = "MUD_RELIABLE_TEST_OK";
enum { port_server = 20000, port_client = 20001 };

static int
run_server(void)
{
    union mud_sockaddr local = {
        .sin = {
            .sin_family = AF_INET,
            .sin_port = htons(port_server),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        },
    };
    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";
    int aes = 1;
    struct mud *mud = mud_create(&local, key, &aes);

    if (!mud) {
        perror("server mud_create");
        return 2;
    }

    {
        struct mud_conf mc = { .reliable = 2 };

        mud_set(mud, &mc);
    }

    unsigned char buf[512];

    /* ~50s wall-clock max: 2000 * 25ms poll */
    for (unsigned i = 0; i < 2000U; i++) {
        for (int u = 0; u < 4; u++)
            (void)mud_update(mud);

        struct pollfd pfd = {
            .fd = mud_get_fd(mud),
            .events = POLLIN,
        };
        if (poll(&pfd, 1, 25) <= 0)
            continue;

        int r = mud_recv(mud, buf, sizeof(buf));

        if (r == -1) {
            if (errno == EAGAIN)
                continue;
            perror("server mud_recv");
            mud_delete(mud);
            return 3;
        }
        if (r <= 0)
            continue;

        if ((size_t)r != strlen(payload) || memcmp(buf, payload, (size_t)r)) {
            mud_delete(mud);
            return 4;
        }
        mud_delete(mud);
        return 0;
    }

    mud_delete(mud);
    return 5;
}


static int
run_client(void)
{
    union mud_sockaddr local = {
        .sin = {
            .sin_family = AF_INET,
            .sin_port = htons(port_client),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        },
    };
    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";
    int aes = 1;
    struct mud *mud = mud_create(&local, key, &aes);

    if (!mud) {
        perror("client mud_create");
        return 2;
    }

    {
        struct mud_conf mc = { .reliable = 2 };

        mud_set(mud, &mc);
    }

    struct mud_path_conf pc = {
        .local = local,
        .remote.sin = {
            .sin_family = AF_INET,
            .sin_port = htons(port_server),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        },
        .state = MUD_UP,
        .tx_max_rate = 1000 * 1000,
        .rx_max_rate = 1000 * 1000,
    };

    if (mud_set_path(mud, &pc)) {
        perror("mud_set_path");
        mud_delete(mud);
        return 2;
    }

    const size_t plen = strlen(payload);
    unsigned char ibuf[512];

    /* Same control-plane / window pattern as test.c. */
    for (;;) {
        if (mud_update(mud))
            usleep(100000);

        struct pollfd pfd = {
            .fd = mud_get_fd(mud),
            .events = POLLIN,
        };
        switch (poll(&pfd, 1, 0)) {
        case -1:
            perror("poll");
            mud_delete(mud);
            return 3;
        case 1:
            if (mud_recv(mud, ibuf, sizeof(ibuf)) == -1) {
                perror("client mud_recv");
                mud_delete(mud);
                return 3;
            }
            break;
        default:
            break;
        }

        int r = mud_send(mud, payload, plen);

        if (r == -1) {
            int e = errno;

            if (e == EAGAIN)
                continue;

            perror("mud_send");
            mud_delete(mud);
            return 3;
        }
        if (r == (int)plen) {
            mud_delete(mud);
            return 0;
        }
    }
}

int
main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "server"))
        return run_server();
    if (argc >= 2 && !strcmp(argv[1], "client"))
        return run_client();

    pid_t pid = fork();

    if (pid == (pid_t)-1) {
        perror("fork");
        return 1;
    }
    if (pid == 0)
        return run_server();

    int cr = run_client();

    if (cr != 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return cr;
    }

    int st = 0;

    if (waitpid(pid, &st, 0) == (pid_t)-1) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(st))
        return 1;
    return WEXITSTATUS(st);
}
