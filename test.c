#include "mud.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
    if (argc > 2)
        return -1;

    int client = argc == 2;

    union mud_sockaddr local = {
        .sin = {
            .sin_family = AF_INET,
            .sin_port = htons(client + 20000),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        },
    };
    struct mud_key key = {.b = {42}};
    struct mud *mud = mud_create(local, &key);

    if (!mud) {
        perror("mud_create");
        return -1;
    }
    if (client) {
        struct mud_path_conf path_conf = {
            .local = local,
            .remote.sin = {
                .sin_family = AF_INET,
                .sin_port = htons(20000),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            },
            .state = MUD_UP,
            .tx_max_rate = 1000 * 1000,
            .rx_max_rate = 1000 * 1000,
            // use default beat, fixed_rate, loss_limit
        };
        if (mud_set_path(mud, &path_conf)) {
            perror("mud_set_path");
            return -1;
        }
    }
    unsigned char buf[1500];

    for (;;) {
        usleep(1000); // don't use all the cpu
        mud_update(mud);

        if (client) {
            // when there is data, mud_recv() is mandatory
            struct pollfd pollfd = {
                .fd = mud_get_fd(mud),
                .events = POLLIN,
            };
            switch (poll(&pollfd, 1, 0)) {
            case -1:
                perror("poll");
                return -1;
            case 1:
                if (mud_recv(mud, buf, sizeof(buf)) == -1) {
                    perror("mud_recv");
                    return -1;
                }
            }
            // we can safely call mud_send()
            // even if the link is not ready
            int r = mud_send(mud, argv[1], strlen(argv[1]));

            if (r == -1) {
                if (errno == EAGAIN)
                    continue;

                perror("mud_send");
                return -1;
            }
            if (r) break;  // we sent everything, bye :)
        } else {
            int r = mud_recv(mud, buf, sizeof(buf));

            if (r == -1) {
                if (errno == EAGAIN)
                    continue;

                perror("mud_recv");
                return -1;
            }
            if (r) {
                buf[r] = 0;
                fprintf(stderr, "%s\n", buf);
                break;
            }
        }
    }
    mud_delete(mud);

    return 0;
}
