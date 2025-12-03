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
#include <openssl/ssl.h>
#include <openssl/err.h>

struct client {
	int fd;
	char username[MAX_NAME];
	LIST_ENTRY(client) entries;
	SSL *ssl;
	int ssl_established;
};

//Make a socket non blocking
int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
	return 0;
}

void opensslInit() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static void opensslCleanup() {
    EVP_cleanup();
}

// Create SSL_CTX for server
SSL_CTX *createServerCtx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Enforce TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Load server certificate & key
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server certificate (%s)\n", cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server private key (%s)\n", key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify private key corresponds to cert
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Server private key does not match the certificate public key\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set CA for client cert verification if desired
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
        fprintf(stderr, "Warning: could not load CA file (%s). Continuing anyway.\n", ca_file);
        ERR_clear_error();
    }

    // Don't require client certificates
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

// Wrapper for a non-blocking SSL accept step.
// Returns:
//   1  = SSL_accept completed successfully
//   0  = still in progress (WANT_READ/WRITE)
//  -1  = fatal error
int ssl_do_accept_nonblocking(SSL *ssl) {
    int rc = SSL_accept(ssl);
    if (rc == 1) return 1;
    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return 0;
    }
    ERR_print_errors_fp(stderr);
    return -1;
}

// Non-blocking SSL read. Returns:
//  >0 bytes read, 0 = orderly shutdown (peer closed), -2 = want read/write (would block), -1 = error
ssize_t ssl_read_nb(SSL *ssl, void *buf, size_t len) {
    int rc = SSL_read(ssl, buf, (int)len);
    if (rc > 0) return rc;
    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return -2;
    if (err == SSL_ERROR_ZERO_RETURN) return 0; // clean shutdown
    ERR_print_errors_fp(stderr);
    return -1;
}

// Non-blocking SSL write. Returns:
//  >0 bytes written, -2 = want read/write (would block), -1 = error
ssize_t ssl_write_nb(SSL *ssl, const void *buf, size_t len) {
    int rc = SSL_write(ssl, buf, (int)len);
    if (rc > 0) return rc;
    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return -2;
    ERR_print_errors_fp(stderr);
    return -1;
}

int main(int argc, char **argv)
{
	if (argc != 6) {
		fprintf(stderr, "Usage: %s <server name> <port> <server_cert.pem> <server_key.pem> <ca_cert.pem>\n", argv[0]);
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

	//Set the certifications, keys, ca
	char cert_file[MAX] = {'\0'};
	snprintf(cert_file, MAX, "%s", argv[3]);
    char key_file[MAX] = {'\0'};
	snprintf(key_file, MAX, "%s", argv[4]);
    char ca_file[MAX] = {'\0'};
	snprintf(ca_file, MAX, "%s", argv[5]);

	//Initialize SSL
	opensslInit();

	SSL_CTX *ctx = createServerCtx(cert_file, key_file, ca_file);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL_CTX\n");
        return EXIT_FAILURE;
    }

	int listen_fd = -1;
    // Create TCP listening socket
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
	
	// reuse addr
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
    }

    if (set_nonblocking(listen_fd) < 0) {
        perror("set_nonblocking");
        close(listen_fd);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

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
				newc->ssl = NULL;
				newc->ssl_established = 0;

				// set accepted socket non-blocking
				if (set_nonblocking(newsockfd) < 0) {
					perror("set_nonblocking new client");
					close(newsockfd);
					free(newc);
				} else {
					// Create SSL object and attach socket
					SSL *ssl = SSL_new(ctx);
					if (!ssl) {
						fprintf(stderr, "SSL_new failed\n");
						close(newsockfd);
						free(newc);
					} else {
						SSL_set_fd(ssl, newsockfd);
						newc->ssl = ssl;
						LIST_INSERT_HEAD(&clients, newc, entries);
						printf("chat server: new client fd=%d (TLS handshake pending)\n", newsockfd);
						client_count += 1;
					}
				}
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

				// If handshake not yet established, try non-blocking accept/handshake
				if (c->ssl && !c->ssl_established) {
					int hs = ssl_do_accept_nonblocking(c->ssl);
					if (hs == 1) {
						c->ssl_established = 1;
						printf("chat server: TLS handshake completed for fd=%d\n", c->fd);
						// send nothing here: client will send username or message next
					} else if (hs == 0) {
						// handshake still in progress; nothing else to do this iteration
					} else {
						// fatal error during handshake
						printf("chat server: TLS handshake failed for fd=%d\n", c->fd);
						client_count -= 1;
						close(c->fd);
						if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
						LIST_REMOVE(c, entries);
						free(c);
					}
					c = tmp;
					continue;
				}

				// Only attempt application read if TLS established
				ssize_t nread = -1;
				if (c->ssl && c->ssl_established) {
					nread = ssl_read_nb(c->ssl, readbuf, MAX);
					if (nread == -2) {
						// would block, skip
						c = tmp;
						continue;
					} else if (nread == 0) {
						// orderly shutdown by peer
						printf("chat server: client \"%s\" (fd=%d) disconnected\n", c->username, c->fd);
						client_count -= 1;
						if (c->username[0] != '\0') {
							snprintf(writebuf, MAX, "(-) %s left the chat.", c->username);
							LIST_FOREACH(other, &clients, entries) {
								if (other != c && other->username[0] != '\0' && other->ssl && other->ssl_established) {
									(void) ssl_write_nb(other->ssl, writebuf, MAX);
								}
							}
						}
						close(c->fd);
						SSL_free(c->ssl);
						LIST_REMOVE(c, entries);
						free(c);
						c = tmp;
						continue;
					} else if (nread < 0) {
						fprintf(stderr, "%s:%d SSL read error on fd=%d\n", __FILE__, __LINE__, c->fd);
						client_count -= 1;
						close(c->fd);
						if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
						LIST_REMOVE(c, entries);
						free(c);
						c = tmp;
						continue;
					}
				} else {
					// No SSL object? fall back to plain read (shouldn't happen in this TLS-enabled build)
					nread = read(c->fd, readbuf, MAX);
				}

				if (nread <= 0) {
					// handled above for TLS; plain read path would fall here
					if (nread < 0) {
						printf("chat server: client \"%s\" (fd=%d) read error or disconnected\n", c->username, c->fd);
					}
					// close & cleanup
					client_count -= 1;
					if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
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
								snprintf(err, MAX, "Username \"%s\" is taken, closing connection", requested
								);
								printf("chat server: client fd=%d connection closed after duplicate username \"%s\"\n", c->fd, requested);
								if (c->ssl && c->ssl_established) {
									(void) ssl_write_nb(c->ssl, err, MAX);
								} else {
									write(c->fd, err, MAX);
								}
								close(c->fd);
								if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
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
							if (c->ssl && c->ssl_established) {
								(void) ssl_write_nb(c->ssl, msg, MAX);
							} else {
								write(c->fd, msg, MAX);
							}
							printf("chat server: client fd=%d given username \"%s\"\n", c->fd, c->username);
						}
					}
					// Message sending, first char = 'm'
					else if (readbuf[0] == 'm') {
						if (c->username[0] == '\0') {
							fprintf(stderr, "%s:%d Client with no username sent message\n", __FILE__, __LINE__);
							if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
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
						if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
						close(c->fd);
						LIST_REMOVE(c, entries);
						free(c);
					}
					// Send the reply to all clients except sender
					if (writebuf[0] != '\0') {
						LIST_FOREACH(other, &clients, entries) {
							if (other != c && other->username[0] != '\0') {
								if (other->ssl && other->ssl_established) {
									(void) ssl_write_nb(other->ssl, writebuf, MAX);
								} else {
									write(other->fd, writebuf, MAX);
								}
							}
						}
					}
				}
			}
			c = tmp;
		}
	}
	close(dirsockfd);
	SSL_CTX_free(ctx);
	opensslCleanup();
}