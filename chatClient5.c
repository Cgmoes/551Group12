#include <stdio.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

struct server {
	char ip[16];
	uint16_t port;
	char name[MAX_NAME];
	LIST_ENTRY(server) entries;
};
 
//Initialize OpenSSL library
static void openssl_init(void)
{
    SSL_library_init(); // initialize SSL library
    SSL_load_error_strings(); //load error strings
    OpenSSL_add_ssl_algorithms(); //add SSL algorithms
}

//Create SSL_CTX for client with CA verification
static SSL_CTX *create_client_ctx(const char *ca_file)
{
    const SSL_METHOD *method = TLS_client_method(); // use client method
    SSL_CTX *ctx = SSL_CTX_new(method); // create new context
    if (!ctx) { // check for failure
        fprintf(stderr, "client: Unable to create SSL context\n"); // debug
        ERR_print_errors_fp(stderr); // debug
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION); // set min version
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); // set max version

    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) { //verify locations
        fprintf(stderr, "client: Failed to load CA file '%s'\n", ca_file); // debug
        ERR_print_errors_fp(stderr); //debug
        SSL_CTX_free(ctx); //free context
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // require server certificate verification

    return ctx;
}

// verify that the servers certificate common name matches expected_name
static int verify_server_name(SSL *ssl, const char *expected_name) 
{
    X509 *cert = SSL_get_peer_certificate(ssl); // get server's certificate
    if (!cert) { //no cert presented for debug
        fprintf(stderr, "client: no server certificate presented\n");
        return 0;
    }

    char cn[256] = {0};  // buffer for common name
    X509_NAME *subj = X509_get_subject_name(cert); // get subject from certificate
    if (!subj) { //null subject for debug
        fprintf(stderr, "client: Failed to get subject from certificate\n"); // debug
        X509_free(cert); // free certificate
        return 0;
    }

    int len = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn)); // get common name
    if (len < 0) { //error getting CN for debug
        fprintf(stderr, "client: Failed to get CN from certificate\n"); // debug
        X509_free(cert); // free certificate
        return 0;
    }
	
    cn[sizeof(cn) - 1] = '\0'; // ensure null termination
    int ok = (strncmp(cn, expected_name, MAX_NAME) == 0); // compare CN with expected name
    if (!ok) { //mismatch for debug
        fprintf(stderr, "client: certificate CN mismatch, Expected \"%s\", got \"%s\"\n", expected_name, cn);
    }
    X509_free(cert); // free certificate
    return ok; // return verification result
}




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
	//write(dirsockfd, input, MAX);
	 if (write(dirsockfd, input, MAX) != MAX) {
        fprintf(stderr, "client: failed to send list request to directory\n");
        close(dirsockfd);
        return EXIT_FAILURE;
    }
	memset(&serv_addr, 0, sizeof(serv_addr));

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
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("client: can't connect to chat server");
		return EXIT_FAILURE;
	}
	    openssl_init();
    const char *ca_file = "tls/ca.crt";

    SSL_CTX *ctx = create_client_ctx(ca_file);
    if (!ctx) {
        close(sockfd);
        return EXIT_FAILURE;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "client: SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(sockfd);
        return EXIT_FAILURE;
    }

    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "client: TLS handshake with chat server failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return EXIT_FAILURE;
    }

    /* Verify server certificate + name (chatroom name) */
    if (!verify_server_name(ssl, /* expected chatroom name = */ input)) {
        fprintf(stderr, "client: server identity verification failed; closing.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("Secure connection (TLS 1.3) established to chatroom \"%s\".\n",
           input);





	char username[MAX_NAME] = {'\0'};
	printf("Connection successful. Enter username: ");
	int c; while ((c = getchar()) != '\n' && c != EOF); // clear input buffer
	if (scanf(" %[^\t\n]", username) == 1) {
        char outbuf[MAX] = {'\0'};
        snprintf(outbuf, MAX, "u%s", username);
        if (SSL_write(ssl, outbuf, MAX) <= 0) {
            fprintf(stderr, "client: failed to send username to server\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            return EXIT_FAILURE;
        }
    } else {
        fprintf(stderr, "%s:%d Error reading or parsing user input\n",
                __FILE__, __LINE__);
    }

	char msg[MAX-1] = {'\0'};
	for(;;) {
		char s[MAX] = {'\0'};
		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

	
        int maxfd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;
        if (select(maxfd + 1, &readset, NULL, NULL, NULL) < 0) {
            perror("client: select on chat server");
            break;
        }

        /* User typed a chat message */
        if (FD_ISSET(STDIN_FILENO, &readset)) {
            if (scanf(" %[^\t\n]", msg) == 1) {
                snprintf(s, MAX, "m%s", msg);
                if (SSL_write(ssl, s, MAX) <= 0) {
                    fprintf(stderr, "client: error sending to server\n");
                    break;
                }
            } else {
                fprintf(stderr, "%s:%d Error reading or parsing user input\n",
                        __FILE__, __LINE__);
            }
        }
  if (FD_ISSET(sockfd, &readset)) {
            ssize_t nread = SSL_read(ssl, s, MAX);
            if (nread <= 0) {
                fprintf(stderr, "%s:%d Error reading from server (TLS)\n",
                        __FILE__, __LINE__);
                break;
            } else {
                printf("%s\n", s);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    return EXIT_SUCCESS;

	
	close(sockfd);
}
