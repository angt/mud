#include "mud.c"
#include "aegis256/aegis256.c"

#include <stdio.h>
#include <poll.h>

int
main(int argc, char **argv)
{
    if (argc > 2)
        return -1;

    int client = argc == 2;

    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = htons(client + 20000),
        .sin_addr = {
            .s_addr = htonl(INADDR_LOOPBACK),
        },
    };

    struct mud *mud = mud_create((struct sockaddr *)&local);

    if (!mud) {
        perror("mud_create");
        return -1;
    }

    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";

    if (mud_set_key(mud, key, sizeof(key))) {
        perror("mud_set_key");
        return -1;
    }

    // client is little harder to setup
    if (client) {
        struct sockaddr_in remote = {
            .sin_family = AF_INET,
            .sin_port = htons(20000),
            .sin_addr = {
                .s_addr = htonl(INADDR_LOOPBACK),
            },
        };

        // we are going to connect to remote...
        if (mud_peer(mud, (struct sockaddr *)&remote)) {
            perror("mud_peer");
            return -1;
        }

        // ...from loopback at 1MBps (not 1Mbps)
        if (mud_set_state(mud, (struct sockaddr *)&local,
                    MUD_UP, 1000 * 1000, 1000 * 1000)) {
            perror("mud_set_state");
            return -1;
        }
    }

    unsigned char buf[1500];

    for (;;) {
        // mandatory, mud have lot of work to do.
        if (mud_send_wait(mud))
            usleep(100000); // don't use all the cpu

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
            int r = mud_send(mud, argv[1], strlen(argv[1]), 0);

            if (r == -1) {
                if (errno == EAGAIN)
                    continue;

                perror("mud_send");
                return -1;
            }

            // we sent everything, bye :)
            if (r)
                break;
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
                printf("%s\n", buf);
            }
        }
    }

    mud_delete(mud);

    return 0;
}
