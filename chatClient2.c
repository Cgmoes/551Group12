#include <stdio.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"

struct server {
	char ip[16];
	uint16_t port;
	char name[MAX_NAME];
	LIST_ENTRY(server) entries;
};

int main()
{
	int dirsockfd, sockfd;
	struct sockaddr_in dir_addr, serv_addr;
	fd_set readset;

	// Define server list head
	LIST_HEAD(server_list, server);
	struct server_list servers = LIST_HEAD_INITIALIZER(servers);

	// Setup connection to directory server
	memset((char *) &dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family			= AF_INET;
	dir_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	dir_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Create a socket (an endpoint for communication). */
	if ((dirsockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(dirsockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
		perror("client: can't connect to directory server");
		return EXIT_FAILURE;
	}

	printf("Please enter the name of the desired chat room:\n");
	char input[MAX] = {'\0'};
	snprintf(input, MAX, "l");
	write(dirsockfd, input, MAX);
	
	for (;;) {
		char s[MAX] = {'\0'};
		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(dirsockfd, &readset);

		if (select(dirsockfd+1, &readset, NULL, NULL, NULL) > 0)
		{
			// Check whether there's user input to read
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				if (1 == scanf(" %[^\t\n]", input)) {
					int chosen = 0;
					struct server *c, *tmp;
					LIST_FOREACH(c, &servers, entries) {
						if (strncmp(c->name, input, MAX_NAME) == 0) {
							printf("Connecting to chatroom \"%s\"...\n", c->name);
							chosen = 1;
							memset((char *) &serv_addr, 0, sizeof(serv_addr));
							serv_addr.sin_family			= AF_INET;
							serv_addr.sin_addr.s_addr	= inet_addr(c->ip);
							serv_addr.sin_port			= htons(c->port);
							break;
						}
					}
					if (!chosen) {
						printf("\"%s\" is not an available chat server. Try again:\n", input);
						snprintf(input, MAX, "l");
						write(dirsockfd, input, MAX);
						continue;
					}
					
					// Free all list memory, we no longer need to store the available servers
					for (c = LIST_FIRST(&servers); c != NULL; ) {
						tmp = LIST_NEXT(c, entries);
						LIST_REMOVE(c, entries);
						free(c);
						c = tmp;
					}
					break;
				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__);
				}
			}

			// If the directory server sent info about a chat server, parse it
			if (FD_ISSET(dirsockfd, &readset)) {
				ssize_t nread = read(dirsockfd, s, MAX);
				if (nread <= 0) {
					fprintf(stderr, "%s:%d Error reading from directory server\n", __FILE__, __LINE__);
					return EXIT_FAILURE;
				} else {
					if (s[0] == 'l') {
						char ip[16];
						char name[MAX_NAME];
						uint16_t port;
						if (sscanf(s + 1, "%[^:]::%hu::%[^:]", ip, &port, name) == 3) {
							struct server *s = malloc(sizeof(struct server));
							snprintf(s->ip, 16, "%s", ip);
							snprintf(s->name, MAX_NAME, "%s", name);
							s->port = port;
							LIST_INSERT_HEAD(&servers, s, entries);
							printf("- Chatroom \"%s\"\n", s->name);
						}
					}
					else {
						fprintf(stderr, "%s:%d Directory server sent undefined data\n", __FILE__, __LINE__);
						return EXIT_FAILURE;
					}
				}
			}
		}
	}
	close(dirsockfd);
	
	// Connect to selected server
	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("client: can't connect to chat server");
		return EXIT_FAILURE;
	}

	char username[MAX_NAME] = {'\0'};
	printf("Connection successful. Enter username: ");
	int c; while ((c = getchar()) != '\n' && c != EOF); // clear input buffer
	// FIXME: Please remember to use the output of scan functions to check if the variables being manipulated were correctly changed.
	scanf("%[^\t\n]", username);
	snprintf(input, MAX, "u%s", username);
	write(sockfd, input, MAX);

	char msg[MAX-1] = {'\0'};
	for(;;) {
		char s[MAX] = {'\0'};
		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

		if (select(sockfd+1, &readset, NULL, NULL, NULL) > 0)
		{
			// Check whether there's user input to read
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				if (1 == scanf(" %[^\t\n]", msg)) {
					// Send the user's message to the server
					snprintf(s, MAX, "m%s", msg);
					write(sockfd, s, MAX);
				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__);
				}
			}

			// Check whether there's a message from the server to read
			if (FD_ISSET(sockfd, &readset)) {
				ssize_t nread = read(sockfd, s, MAX);
				if (nread <= 0) {
					fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__);
					return EXIT_FAILURE;
				} else {
					printf("%s\n", s);
				}
			}
		}
	}
	close(sockfd);
}
