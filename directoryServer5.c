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
static int verify_chatserver_cert(SSL *ssl);
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

				// No TLS until a registration request is received
				printf("directory: new connection fd=%d (ip=%s)\n", newc->fd, newc->ip);

				// Insert into client list
				LIST_INSERT_HEAD(&clients, newc, entries);
			}
		}

		// Read the request from the client(s)
		struct client *tmp, *other;
		for (c = LIST_FIRST(&clients); c != NULL; ) {
			tmp = LIST_NEXT(c, entries);
			if (FD_ISSET(c->fd, &readset)) {
				char readbuf[MAX] = {'\0'};
				char writebuf[MAX] = {'\0'};
				ssize_t nread = client_recv(c, readbuf, sizeof(readbuf));
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
				} else {
					// Registration: Chat servers perform TLS handshake now, then register.
					if (readbuf[0] == 'r') {
						// If TLS has not yet been established for this client, do it now
						if (!c->tls_handshake_done) {
							SSL *ssl = SSL_new(ctx);
							if (!ssl) {
								fprintf(stderr, "directory: SSL_new failed\n");
								// close and cleanup
								if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
								c = tmp;
								continue;
							}
							SSL_set_fd(ssl, c->fd);

							if (SSL_accept(ssl) <= 0) {
								fprintf(stderr, "directory: TLS handshake failed (fd=%d)\n", c->fd);
								ERR_print_errors_fp(stderr);
								SSL_free(ssl);
								// close and cleanup
								if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
								c = tmp;
								continue;
							}

							// Verify certificate common name is allowed
							long v = SSL_get_verify_result(ssl);
							if (v != X509_V_OK) {
								fprintf(stderr, "directory: certificate verification failed (fd=%d): %ld\n", c->fd, v);
								SSL_shutdown(ssl);
								SSL_free(ssl);
								// close and cleanup
								if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
								c = tmp;
								continue;
							}
							if (!verify_chatserver_cert(ssl)) {
								fprintf(stderr, "directory: rejected connection: certificate CN not allowed (fd=%d)\n", c->fd);
								SSL_shutdown(ssl);
								SSL_free(ssl);
								// close and cleanup
								if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
								c = tmp;
								continue;
							}

							// TLS handshake successful and cert OK -> use this SSL for client
							c->ssl = ssl;
							c->tls_handshake_done = 1;
							printf("directory: TLS established for registration fd=%d (ip=%s)\n", c->fd, c->ip);
							ssize_t secure_read = client_recv(c, readbuf, sizeof(readbuf));
							if (secure_read <= 0) {
								fprintf(stderr, "%s:%d Failed to read registration after TLS handshake from fd=%d\n",
									__FILE__, __LINE__, c->fd);
								// cleanup
								if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
								c = tmp;
								continue;
							}
						}

						char requested[MAX_NAME];
						int port;
						int available = 1;
						int sscanf_res = -1;

						if (readbuf[0] == 'r') {
							sscanf_res = sscanf(readbuf + 1, "%[^:]::%d", requested, &port);
						} 
						if (sscanf_res == 2) {
							// Check duplicate names among registered servers
							for (other = LIST_FIRST(&clients); other != NULL; ) {
								struct client *next_other = LIST_NEXT(other, entries);
								if (other->chatname[0] != '\0' &&
									strncmp(other->chatname, requested, MAX_NAME) == 0) {
									available = 0;
									printf("directory: fd=%d tried to register with duplicate name %s\n", c->fd, requested);
									break;
								}
								other = next_other;
							}
							if (server_count < MAX_SERVERS && available) {
								c->port = port;
								snprintf(c->chatname, MAX_NAME, "%s", requested);
								printf("directory: fd=%d hosting \"%s\" at %s:%d\n", c->fd, c->chatname, c->ip, c->port);
								server_count += 1;
							} else {
								// Too many servers or duplicate
								printf("directory: closed fd=%d (too many servers or dup)\n", c->fd);
								if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
								close(c->fd);
								LIST_REMOVE(c, entries);
								free(c);
							}
						} else {
							fprintf(stderr, "%s:%d Received an invalid register request from %d\n", __FILE__, __LINE__, c->fd);
							if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
							close(c->fd);
							LIST_REMOVE(c, entries);
							free(c);
						}
					}

					// List active chat servers (plaintext list requests from clients)
					else if (readbuf[0] == 'l') {
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
			c = tmp;
		}
	}

	// Should never be reached, but just in case
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
	if (SSL_CTX_use_certificate_file(ctx, "dirserver.crt", SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to load dirserver.crt\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "dirserver.key", SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to load dirserver.key\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Load CA that signs Chat Servers' certs
	if (SSL_CTX_load_verify_locations(ctx, "chatserver_ca.crt", NULL) <= 0) {
		fprintf(stderr, "Failed to load chatserver_ca.crt\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Require peer cert and verify it
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);
}

// Verifies the peer's certificate CN is one of the allowed list
static int verify_chatserver_cert(SSL *ssl)
{
	X509 *cert = SSL_get_peer_certificate(ssl);
	if (!cert) return 0;

	char cn[256] = {0};
	X509_NAME *subj = X509_get_subject_name(cert);
	if (subj) {
		X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
	}
	X509_free(cert);

	const char *allowed[] = { "Chat1", "Chat2", "Chat3", "Chat4", "Chat5" };
	size_t allowed_count = sizeof(allowed) / sizeof(allowed[0]);

	for (size_t i = 0; i < allowed_count; ++i) {
		if (strncmp(cn, allowed[i], MAX) == 0) return 1;
	}
	return 0;
}

// Receive from client (TLS or plaintext). Returns bytes read or <=0 on error/close
static ssize_t client_recv(struct client *c, char *buf, size_t len)
{
	if (c->ssl) {
		int r = SSL_read(c->ssl, buf, (int)len - 1);
		if (r <= 0) {
			int err = SSL_get_error(c->ssl, r);
			(void)err;
			return -1;
		}
		if ((size_t)r < len) buf[r] = '\0';
		else buf[len - 1] = '\0';
		return r;
	} else {
		ssize_t r = read(c->fd, buf, len - 1);
		if (r <= 0) return r;
		buf[r] = '\0';
		return r;
	}
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
	} else {
		ssize_t r = write(c->fd, buf, len);
		return r;
	}
}

