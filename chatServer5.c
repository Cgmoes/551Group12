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
#include <fcntl.h>    // added for fcntl
#include <errno.h>    // added for errno

// -----------------------------
// ADDED: keyfile lock struct + functions
// -----------------------------
struct keyfile_lock {
    int fd;
    struct flock fl;
};

int lock_keyfile(struct keyfile_lock *lk, const char *key_file)
{
    lk->fd = open(key_file, O_RDONLY);
    if (lk->fd < 0) {
        perror("open key_file");
        return -1;
    }

    memset(&lk->fl, 0, sizeof(lk->fl));
    lk->fl.l_type = F_WRLCK;
    lk->fl.l_whence = SEEK_SET;
    lk->fl.l_start = 0;
    lk->fl.l_len = 0;

    if (fcntl(lk->fd, F_SETLK, &lk->fl) < 0) {
        perror("fcntl key_file lock");
        close(lk->fd);
        return -1;
    }

    return 0;
}

void unlock_keyfile(struct keyfile_lock *lk)
{
    lk->fl.l_type = F_UNLCK;
    fcntl(lk->fd, F_SETLK, &lk->fl);
    close(lk->fd);
}

// -----------------------------

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

// Create SSL_CTX for server or client (is_server: 1=server,0=client)
SSL_CTX *createCtx(int is_server, const char *cert_file, const char *key_file) {

    // -----------------------------
    // ADDED: Key file locking BEFORE OpenSSL loads it
    // -----------------------------
    static struct keyfile_lock keylock;
    if (is_server) {
        if (lock_keyfile(&keylock, key_file) < 0) {
            fprintf(stderr, "Failed to lock key file %s\n", key_file);
            return NULL;
        }
        printf("Key file %s locked.\n", key_file);
    }
    // -----------------------------

    const SSL_METHOD *method = is_server ? TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (is_server) {
        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ||
            !SSL_CTX_check_private_key(ctx)) {

            fprintf(stderr, "Server cert/key load error\n");
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

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
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <server name> <port> <server_cert.pem> <server_key.pem>\n", argv[0]);
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
	SSL *dir_ssl = NULL;
	struct sockaddr_in cli_addr, serv_addr, dir_addr;
	fd_set readset;
	int client_count = 0;

	char cert_file[MAX] = {'\0'};
	snprintf(cert_file, MAX, "%s", argv[3]);
    char key_file[MAX] = {'\0'};
	snprintf(key_file, MAX, "%s", argv[4]);
    char ca_file[MAX] = {'\0'};
	snprintf(ca_file, MAX, "%s", argv[5]);

	opensslInit();

	SSL_CTX *ctx = createCtx(1, cert_file, key_file);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL_CTX\n");
        return EXIT_FAILURE;
    }

	SSL_CTX *dir_ctx = createCtx(0, cert_file, key_file);
    if (!dir_ctx) {
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

	memset((char *) &dir_addr, 0, sizeof(dir_addr));
	dir_addr.sin_family			= AF_INET;
	dir_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);
	dir_addr.sin_port			= htons(SERV_TCP_PORT);

	if ((dirsockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("chat server: can't open stream socket");
		return EXIT_FAILURE;
	}

    if (set_nonblocking(dirsockfd) < 0) {
        perror("set_nonblocking directory socket");
        close(dirsockfd);
        return EXIT_FAILURE;
    }

    int rc = connect(dirsockfd, (struct sockaddr *) &dir_addr, sizeof(dir_addr));
    if (rc < 0 && errno != EINPROGRESS) {
        perror("chat server: can't connect to directory server");
        close(dirsockfd);
        return EXIT_FAILURE;
    }

    dir_ssl = SSL_new(dir_ctx);
    if (!dir_ssl) {
        fprintf(stderr, "SSL_new failed for directory server\n");
        close(dirsockfd);
        return EXIT_FAILURE;
    }
    SSL_set_fd(dir_ssl, dirsockfd);

    while (1) {
        rc = SSL_connect(dir_ssl);
        if (rc == 1) {
            printf("chat server: TLS handshake completed with directory server\n");
            break;
        }
        int err = SSL_get_error(dir_ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            fd_set rset, wset;
            FD_ZERO(&rset);
            FD_ZERO(&wset);
            if (err == SSL_ERROR_WANT_READ) FD_SET(dirsockfd, &rset);
            if (err == SSL_ERROR_WANT_WRITE) FD_SET(dirsockfd, &wset);
            if (select(dirsockfd + 1, &rset, &wset, NULL, NULL) < 0) {
                perror("select during SSL_connect");
                SSL_free(dir_ssl);
                close(dirsockfd);
                return EXIT_FAILURE;
            }
            continue;
        }
        fprintf(stderr, "TLS handshake failed with directory server\n");
        ERR_print_errors_fp(stderr);
        SSL_free(dir_ssl);
        close(dirsockfd);
        return EXIT_FAILURE;
    }

	char smsg[MAX] = {'\0'};
	snprintf(smsg, MAX, "r%s::%d::%s", name, port, cert_file);
	(void) ssl_write_nb(dir_ssl, smsg, MAX);

	LIST_HEAD(client_list, client);
	struct client_list clients = LIST_HEAD_INITIALIZER(clients);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s:%d Can't open stream socket\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		fprintf(stderr, "%s:%d Can't set stream socket address reuse option\n", __FILE__, __LINE__);
		return EXIT_FAILURE;
	}

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

		if (FD_ISSET(sockfd, &readset)) {
			socklen_t clilen = sizeof(cli_addr);
			newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
			if (newsockfd < 0) {
				fprintf(stderr, "%s:%d Accept error\n", __FILE__, __LINE__);
				return EXIT_FAILURE;
			}

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

				if (set_nonblocking(newsockfd) < 0) {
					perror("set_nonblocking new client");
					close(newsockfd);
					free(newc);
				} else {
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

		struct client *other, *tmp;
		for (c = LIST_FIRST(&clients); c != NULL; ) {
			tmp = LIST_NEXT(c, entries);
			if (FD_ISSET(c->fd, &readset)) {
				char readbuf[MAX] = {'\0'};
				char writebuf[MAX] = {'\0'};

				if (c->ssl && !c->ssl_established) {
					int hs = ssl_do_accept_nonblocking(c->ssl);
					if (hs == 1) {
						c->ssl_established = 1;
						printf("chat server: TLS handshake completed for fd=%d\n", c->fd);
					} else if (hs == 0) {
					} else {
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

				ssize_t nread = -1;
				if (c->ssl && c->ssl_established) {
					nread = ssl_read_nb(c->ssl, readbuf, MAX);
					if (nread == -2) {
						c = tmp;
						continue;
					} else if (nread == 0) {
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
					nread = read(c->fd, readbuf, MAX);
				}

				if (nread <= 0) {
					if (nread < 0) {
						printf("chat server: client \"%s\" (fd=%d) read error or disconnected\n", c->username, c->fd);
					}
					client_count -= 1;
					if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
					close(c->fd);
					LIST_REMOVE(c, entries);
					free(c);
				} else {
					if (readbuf[0] == 'u') {
						char requested[MAX_NAME];
						sscanf(readbuf+1, "%[^\t\n]", requested);

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
							snprintf(c->username, MAX_NAME, "%s", requested);
							snprintf(writebuf, MAX, "(+) %s joined the chat.", c->username);
							char msg[MAX] = {'\0'};

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
	EVP_cleanup();

    // -----------------------------
    // ADDED: Unlock keyfile at shutdown
    // -----------------------------
    // (Safe because `createCtx()` locked it statically.)
    extern struct keyfile_lock keylock;
    unlock_keyfile(&keylock);
    // -----------------------------
}