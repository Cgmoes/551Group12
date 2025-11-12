#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include "inet.h"
#include "common.h"


struct client {
	int fd;
	int port;
	char ip[16];
	char chatname[MAX_NAME];
	LIST_ENTRY(client) entries;
};

int main(int argc, char **argv)
{
	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return EXIT_FAILURE;
	}
	int sockfd, newsockfd;
	struct sockaddr_in cli_addr, serv_addr;
	fd_set readset;
	int server_count = 0;

	// Define client list head
	LIST_HEAD(client_list, client);
	struct client_list clients = LIST_HEAD_INITIALIZER(clients);

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDRR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family		= AF_INET;
	serv_addr.sin_addr.s_addr 	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */


	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	listen(sockfd, 5);

	for (;;) {

		// Initialize and populate readset and compute maxfd
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		int max_fd = sockfd;

		struct client *c;
		LIST_FOREACH(c, &clients, entries) {
			FD_SET(c->fd, &readset);
			if (c->fd > max_fd) {
				max_fd = c->fd;
			}
	}

		if (select(max_fd+1, &readset, NULL, NULL, NULL) <= 0) {
			fprintf(stderr, "%s:%d Select error\n", __FILE__, __LINE__);
			continue;
		}

		// Check to see if our listening socket has a pending connection
		if (FD_ISSET(sockfd, &readset)) {
			socklen_t clilen = sizeof(cli_addr);
			newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
			if (newsockfd < 0) {
				fprintf(stderr, "%s:%d Accept error\n", __FILE__, __LINE__);
				return EXIT_FAILURE;
			}
			// Add client to the list
			struct client *newc = malloc(sizeof(*newc));
			if (newc == NULL) {
				fprintf(stderr, "%s:%d Malloc error\n", __FILE__, __LINE__);
				close(newsockfd);
				free(newc);
			} else {
				if (inet_ntop(AF_INET, &cli_addr.sin_addr, newc->ip, sizeof(newc->ip)) == NULL) {
					fprintf(stderr, "%s:%d Error storing IP\n", __FILE__, __LINE__);
				}
				newc->fd = newsockfd;
				newc->port = -1;
				newc->chatname[0] = '\0';
				LIST_INSERT_HEAD(&clients, newc, entries);
				printf("directory: new connection fd=%d\n", newsockfd);
			}
		}

		// Read the request from the client
		struct client *tmp, *other;
		for (c = LIST_FIRST(&clients); c != NULL; ) {
			tmp = LIST_NEXT(c, entries);
			if (FD_ISSET(c->fd, &readset)) {
				char readbuf[MAX] = {'\0'};
				char writebuf[MAX] = {'\0'};
				ssize_t nread = read(c->fd, readbuf, MAX);

				// If client disconnected, remove them from the list
				if (nread <= 0) {
					if (c->chatname[0] == '\0') {
						printf("directory: client (fd=%d) disconnected\n", c->fd);
					} else {
						printf("directory: chat server \"%s\" (fd=%d) offline\n", c->chatname, c->fd);
						server_count -= 1;
					}
					close(c->fd);
					LIST_REMOVE(c, entries);
					free(c);
				} else {
					// Chat name choosing, formatted: "r{name}::{port}"
					if (readbuf[0] == 'r') {
						char name[MAX_NAME];
						int port;
				    if (sscanf(readbuf + 1, "%[^:]::%d", name, &port) == 2) {
				    	if (server_count < MAX_SERVERS) {
					    	c->port = port;
					    	snprintf(c->chatname, MAX_NAME, "%s", name);
								printf(
									"directory: fd=%d hosting \"%s\" at %s:%d\n",
									c->fd, c->chatname, c->ip, c->port
					    	);
								server_count += 1;
				    	} 
				    	else {
				    		// If there are already MAX_SERVERS servers registered, close connection
				    		printf("directory: closed fd=%d, already at max chat servers\n", c->fd);
				    		close(c->fd);
				    		LIST_REMOVE(c, entries);
				    		free(c);
				    	}
				    }
				    else {
							fprintf(stderr,
								"%s:%d Received an undefined request from %d\n",
								__FILE__, __LINE__, c->fd
							);
							close(c->fd);
							LIST_REMOVE(c, entries);
							free(c);
				    }
					}

					// List active chat servers, always sent as "l"
					else if (readbuf[0] == 'l') {
						LIST_FOREACH(other, &clients, entries) {
							// Only list clients with chatnames (this signifies it is a currently active server)
							if (other->fd != c->fd && other->chatname[0] != '\0') {
				        snprintf(writebuf, sizeof(writebuf), "l%s::%d::%s",
              		other->ip, other->port, other->chatname);
				        write(c->fd, writebuf, MAX);
							}
						}
					}
					
					// No idea how this would happen, but it's here just in case
					else {
						fprintf(stderr,
							"%s:%d Received an undefined request from %d\n",
							__FILE__, __LINE__, c->fd
						);
						close(c->fd);
						LIST_REMOVE(c, entries);
						free(c);
					}
				}
			}
			c = tmp;
		}
	}
}
