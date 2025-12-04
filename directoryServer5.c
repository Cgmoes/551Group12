#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include "inet.h"
#include "common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

struct client {
	int fd;
	int port;
	char ip[16];
	char chatname[MAX_NAME];
	SSL *ssl;
	int tls_handshake_done;
	LIST_ENTRY(client) entries;
};

static SSL_CTX *create_ssl_context(void);
static void configure_ssl_context(SSL_CTX *ctx);
static ssize_t client_recv(struct client *c, char *buf, size_t len);
static ssize_t client_send(struct client *c, const char *buf, size_t len);

int main(int argc, char **argv)
{
	// Initialize OpenSSL
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	if (argc != 1) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		return EXIT_FAILURE;
	}

	// Configure SSL context for incoming chat server connections
	SSL_CTX *ctx = create_ssl_context();
	configure_ssl_context(ctx);

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
		SSL_CTX_free(ctx);
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDR option to prevent address in use errors */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		close(sockfd);
		SSL_CTX_free(ctx);
		return EXIT_FAILURE;
	}

	/* Bind socket to local address */
	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family		= AF_INET;
	serv_addr.sin_addr.s_addr 	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		close(sockfd);
		SSL_CTX_free(ctx);
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
			newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
			if (newsockfd < 0) {
				fprintf(stderr, "%s:%d Accept error: %s\n", __FILE__, __LINE__, strerror(errno));
				continue;
			}

			// Allocate new client structure
			struct client *newc = malloc(sizeof(*newc));
			if (newc == NULL) {
				fprintf(stderr, "%s:%d Malloc error\n", __FILE__, __LINE__);
				close(newsockfd);
			} else {
				if (inet_ntop(AF_INET, &cli_addr.sin_addr, newc->ip, sizeof(newc->ip)) == NULL) {
					fprintf(stderr, "%s:%d Error storing IP\n", __FILE__, __LINE__);
				}
				newc->fd = newsockfd;
				newc->port = -1;
				newc->chatname[0] = '\0';
				newc->ssl = NULL;
				newc->tls_handshake_done = 0;

				printf("directory: new connection fd=%d (ip=%s)\n", newc->fd, newc->ip);

				// Require TLS handshake
				SSL *ssl = SSL_new(ctx);
				if (ssl) {
					SSL_set_fd(ssl, newc->fd);
					if (SSL_accept(ssl) > 0) {
				    newc->ssl = ssl;
				    newc->tls_handshake_done = 1;
				    printf("directory: TLS established for fd=%d\n", newc->fd);
						LIST_INSERT_HEAD(&clients, newc, entries);
					} else {
				    printf("directory: TLS error for fd=%d, closing connection\n", newc->fd);
				    SSL_free(ssl);
				    close(newc->fd);
				    free(newc);
				    continue;
					}
				}
			}
		}

		// Read the request from the client(s)
		struct client *tmp, *other;
		for (c = LIST_FIRST(&clients); c != NULL; c = tmp) {
			tmp = LIST_NEXT(c, entries);
			if (FD_ISSET(c->fd, &readset)) {
				char readbuf[MAX] = {'\0'};
				char writebuf[MAX] = {'\0'};
				ssize_t nread = client_recv(c, readbuf, MAX);
				if (nread <= 0) {
					// Client disconnected
					if (c->chatname[0] == '\0') {
						printf("directory: client (fd=%d) disconnected\n", c->fd);
					} else {
						printf("directory: chat server \"%s\" (fd=%d) offline\n", c->chatname, c->fd);
						server_count -= 1;
					}

					// Clean up SSL if present
					if (c->ssl) {
						SSL_shutdown(c->ssl);
						SSL_free(c->ssl);
					}
					close(c->fd);
					LIST_REMOVE(c, entries);
					free(c);
					continue;
				} else {
					if (c->tls_handshake_done) {
						// Registration: Chat server registers it's name for clients to see
						if (readbuf[0] == 'r') {
							char requested[MAX_NAME];
							int port;
							int available = 1;

							int sscanf_res = sscanf(readbuf + 1, "%[^:]::%d", requested, &port);

							if (sscanf_res == 2) {
								LIST_FOREACH(other, &clients, entries) {
									if (other->chatname[0] != '\0' &&
										strncmp(other->chatname, requested, MAX_NAME) == 0) {

										available = 0;
										printf("directory: fd=%d duplicate name %s\n",
										c->fd, requested);
										break;
									}
								}

								if (server_count < MAX_SERVERS && available) {
									c->port = port;
									snprintf(c->chatname, MAX_NAME, "%s", requested);
									printf("directory: fd=%d hosting \"%s\" at %s:%d\n",
									c->fd, c->chatname, c->ip, c->port);
									server_count += 1;
								} else {
									printf("directory: closed fd=%d (too many or dup)\n", c->fd);
									if (c->ssl) {
										SSL_shutdown(c->ssl);
										SSL_free(c->ssl);
									}
									close(c->fd);
									LIST_REMOVE(c, entries);
									free(c);
									continue;
								}
							} else {
								fprintf(stderr, "Invalid register request from fd=%d\n", c->fd);
								if (c->ssl) {
									SSL_shutdown(c->ssl);
									SSL_free(c->ssl);
								}
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
								continue;
							}
						}

						// List active chat servers
						else if (readbuf[0] == 'l') {
							printf("directory: sent fd=%d list of servers\n", c->fd);
							for (other = LIST_FIRST(&clients); other != NULL; other = LIST_NEXT(other, entries)) {
								// Only list clients with chatnames (registered chat servers)
								if (other->fd != c->fd && other->chatname[0] != '\0') {
									snprintf(writebuf, sizeof(writebuf), "l%s::%d::%s",
										other->ip, other->port, other->chatname
									);
									client_send(c, writebuf, MAX);
								}
							}
						}

						// Unknown request
						else {
							fprintf(stderr,
								"%s:%d Received an undefined request from %d\n",
								__FILE__, __LINE__, c->fd
							);
							if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
							close(c->fd);
							LIST_REMOVE(c, entries);
							free(c);
						}
					}
				}
			}
		}
	}

	printf("directory: Exiting main loop");
	SSL_CTX_free(ctx);
	close(sockfd);
	return EXIT_SUCCESS;
}

/* ------------------------ Helper functions ------------------------ */

// Create an SSL_CTX for TLS server use
static SSL_CTX *create_ssl_context(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

// Configure server certificate, key, and CA
static void configure_ssl_context(SSL_CTX *ctx)
{
	// Directory server certificate and key
	if (SSL_CTX_use_certificate_file(ctx, "tls/directoryServer.crt", SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to load directory server cert\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "tls/directoryServer.key", SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to load directory server key\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

// Receive from client (TLS or plaintext). Returns bytes read or <=0 on error/close
ssize_t client_recv(struct client *c, char *buf, size_t sz) {
    if (!c->ssl) return read(c->fd, buf, sz);
		int n = SSL_read(c->ssl, buf, sz);
		if (n > 0) return n;

		int err = SSL_get_error(c->ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) {
        // clean TLS shutdown
        return 0;
    }

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return -2;
    }

    // ERROR
    return -1;
}

// Send to client (TLS or plaintext). Returns bytes written or -1 on error
static ssize_t client_send(struct client *c, const char *buf, size_t len)
{
	if (c->ssl) {
		int r = SSL_write(c->ssl, buf, (int)len);
		if (r <= 0) {
			int err = SSL_get_error(c->ssl, r);
			(void)err;
			return -1;
		}
		return r;
	}
	return -1;
}

