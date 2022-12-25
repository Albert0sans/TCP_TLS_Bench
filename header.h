
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
static const int server_port = 5000;

typedef unsigned char   bool;
#define true            1
#define false           0


#define BUFF_LEN 1000
static volatile bool    server_running = true;

int create_socket(bool isServer);
SSL_CTX* create_context(bool isServer);
void configure_server_context(SSL_CTX *ctx);
void configure_client_context(SSL_CTX *ctx);
void exit_s(SSL_CTX *ssl_ctx,SSL *ssl,int client_skt,int server_skt);
void client( struct sockaddr_in addr,SSL_CTX *ssl_ctx,SSL *ssl,char* buf,size_t len,char *rem_server_ip,int num_pk);
void server(SSL_CTX *ssl_ctx,SSL *ssl,char* buf,size_t len);
void usage();
double elapsed_time(struct timeval *tv_first, struct timeval *tv_end);
void stats(struct timeval *tv_first, struct timeval *tv_end, unsigned int numpkts_rx, unsigned int numbytes_rx);

