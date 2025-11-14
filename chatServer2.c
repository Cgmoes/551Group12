#include <asm-generic/socket.h>
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
	char username[MAX_NAME];
	LIST_ENTRY(client) entries;
};

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <server name> <port>\n", argv[0]);
		return EXIT_FAILURE;
	}
	char name[MAX_NAME] = {'\0'};
	snprintf(name, MAX_NAME, "%s", argv[1]);
	unsigned int temp;
	if (sscanf(argv[2], "%u", &temp) != 1 || temp > 65535) {
    fprintf(stderr, "Invalid port number\n");
    exit(EXIT_FAILURE);
	}
	in_port_t port = (in_port_t)temp;
	int sockfd, newsockfd, dirsockfd;
	struct sockaddr_in cli_addr, serv_addr, dir_addr;
	fd_set readset;
	int client_count = 0;

	// ---- Setting up directory server communication ----
	// Set up the address of directory server
	memset((char *) &dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family			= AF_INET;
	dir_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	dir_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Create a socket (an endpoint for communication). */
	if ((dirsockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("chat server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(dirsockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
		perror("chat server: can't connect to directory server");
		return EXIT_FAILURE;
	}

	char smsg[MAX] = {'\0'};
	snprintf(smsg, MAX, "r%s::%d", name, port);
	write(dirsockfd, smsg, MAX);
	

	// ---- Setting up client communication ----
	// Define client list head
	LIST_HEAD(client_list, client);
	struct client_list clients = LIST_HEAD_INITIALIZER(clients);

	// Create communication endpoint
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s:%d Can't open stream socket\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}
	
	/* Add SO_REAUSEADDR option to prevent address in use errors (modified from: "Hands-On Network
* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		fprintf(stderr, "%s:%d Can't set stream socket address reuse option\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	// Bind socket to local address
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	serv_addr.sin_port			= htons(port);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		fprintf(stderr, "%s:%d Can't bind local address\n", __FILE__, __LINE__);
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
			} else if (client_count < MAX_CLIENTS) {
				newc->fd = newsockfd;
				newc->username[0] = '\0';
				LIST_INSERT_HEAD(&clients, newc, entries);
				printf("chat server: new client fd=%d\n", newsockfd);
				client_count += 1;
			} else {
				char buf[MAX] = {'\0'};
				snprintf(buf, MAX, "This server is at max capacity. Closing connection.");
				write(newsockfd, buf, MAX);
				close(newsockfd);
				free(newc);
			}
		}

		// Read the request from the client
		struct client *other, *tmp;
		for (c = LIST_FIRST(&clients); c != NULL; ) {
			tmp = LIST_NEXT(c, entries);
			if (FD_ISSET(c->fd, &readset)) {
				char readbuf[MAX] = {'\0'};
				char writebuf[MAX] = {'\0'};
				ssize_t nread = read(c->fd, readbuf, MAX);
				if (nread <= 0) {
					printf("chat server: client \"%s\" (fd=%d) disconnected\n", c->username, c->fd);
					client_count -= 1;
					// Send disconnect notifications
					if (c->username[0] != '\0') {
						snprintf(writebuf, MAX, "(-) %s left the chat.", c->username);
						LIST_FOREACH(other, &clients, entries) {
							if (other != c && other->username[0] != '\0') {
								write(other->fd, writebuf, MAX);
							}
						}
					}
					close(c->fd);
					LIST_REMOVE(c, entries);
					free(c);
				} else {
					// Username choosing, first char = 'u'
					if (readbuf[0] == 'u') {
						char requested[MAX_NAME]; // Requested username
						sscanf(readbuf+1, "%[^\t\n]", requested); 

						// Check to see if username is in use
						int available = 1;
						struct client *tmp2;
						for (other = LIST_FIRST(&clients); other != NULL; ) {
							tmp2 = LIST_NEXT(other, entries);
							if (strncmp(other->username, requested, MAX_NAME) == 0) {
								char err[MAX];
								available = 0;
								snprintf(err, sizeof(err),
				        	"Username \"%s\" is taken, closing connection",
				        	requested
								);
								printf("chat server: client fd=%d connection closed after duplicate username \"%s\"\n", c->fd, requested);
								write(c->fd, err, MAX);
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
								break;
							}
							other = tmp2;
						}
						if (available) {
							// Give username to client and prepare message
							snprintf(c->username, MAX_NAME, "%s", requested);
							snprintf(writebuf, MAX, "(+) %s joined the chat.", c->username);
							char msg[MAX] = {'\0'};

							// Checking whether to send "first user" message
							snprintf(msg, MAX, "You are the first user to join the chat");
							LIST_FOREACH(other, &clients, entries) {
								if (!(other->fd == c->fd) && other->username[0] != '\0') {
									snprintf(msg, MAX, "You have joined the chat.");
									break;
								}
							}
							write(c->fd, msg, MAX);
							printf("chat server: client fd=%d given username \"%s\"\n", c->fd, c->username);
						}
					}
					// Message sending, first char = 'm'
					else if (readbuf[0] == 'm') {
						if (c->username[0] == '\0') {
							fprintf(stderr, "%s:%d Client with no username sent message\n", __FILE__, __LINE__);
							close(c->fd);
							LIST_REMOVE(c, entries);
							free(c);
						} else {
							snprintf(writebuf, MAX, "%s: %s", c->username, readbuf+1);
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
					// Send the reply to all clients except sender
					if (writebuf[0] != '\0') {
						LIST_FOREACH(other, &clients, entries) {
							if (other != c && other->username[0] != '\0') {
								write(other->fd, writebuf, MAX);
							}
						}
					}
				}
			}
			c = tmp;
		}
	}
	close(dirsockfd);
}
