CFLAGS = -g -c -Wall -Werror

all: mpls-ping mpls-daemon

mpls_util.o: mpls_util.c mpls_util.h
	gcc $(CFLAGS) -o mpls_util.o mpls_util.c

mpls_network.o: mpls_network.c mpls_network.h
	gcc $(CFLAGS) -o mpls_network.o mpls_network.c

mpls_packet.o: mpls_packet.c mpls_packet.h
	gcc $(CFLAGS) -o mpls_packet.o mpls_packet.c

mpls_label.o: mpls_label.c mpls_label.h
	gcc $(CFLAGS) -o mpls_label.o mpls_label.c

mpls_ping.o: mpls_ping.c
	gcc $(CFLAGS) -o mpls_ping.o mpls_ping.c

mpls-ping: mpls_ping.o mpls_label.o mpls_packet.o mpls_network.o mpls_util.o
	gcc -o mpls-ping mpls_ping.o mpls_label.o mpls_packet.o mpls_network.o mpls_util.o

mpls_daemon.o: mpls_daemon.c
	gcc $(CFLAGS) -o mpls_daemon.o mpls_daemon.c

mpls-daemon: mpls_daemon.o mpls_label.o mpls_packet.o mpls_network.o mpls_util.o
	gcc -g -o mpls-daemon mpls_daemon.o mpls_label.o mpls_packet.o mpls_network.o mpls_util.o

clean:
	rm -f *.o
	rm -f mpls-daemon
	rm -f mpls-ping
