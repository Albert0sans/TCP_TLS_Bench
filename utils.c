#include "header.h"
int create_socket(bool isServer)
{
    int s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    printf("%d\n",s);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (isServer) {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* Reuse the address; good for quick restarts */
         if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
                < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            exit(EXIT_FAILURE);
        }

        if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        if (listen(s, 1) < 0) {
            perror("Unable to listen");
            exit(EXIT_FAILURE);
        }
    }

    return s;
}

SSL_CTX* create_context(bool isServer)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (isServer)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_server_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void configure_client_context(SSL_CTX *ctx)
{
    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    /*
     * In a real application you would probably just use the default system certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
     */
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
}

void server(SSL_CTX *ssl_ctx,SSL *ssl,char* rxbuf,size_t rxcap)
{
 int server_skt = create_socket(true);
struct timeval tv_last, tv_first;
        printf("We are the server on port: %d\n\n", server_port);
        configure_server_context(ssl_ctx);
       int client_skt=-1;
       int num_ptks=0;
       int rxlen;
       struct sockaddr_in addr;
       unsigned int addr_len = sizeof(addr);
        int total_len=0;
        while (1) {
            /* Wait for TCP connection from client */
            client_skt = accept(server_skt, (struct sockaddr*) &addr,
                    &addr_len);
            if (client_skt < 0) {
                perror("Unable to accept \n");
                exit(EXIT_FAILURE);
            }

            printf("Client TCP connection accepted\n");

            /* Create server SSL structure using newly accepted client socket */
            ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_skt);

            /* Wait for SSL connection from the client */
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                server_running = false;
            } else {
                printf("Client SSL connection accepted\n\n");
                int run=1;
                while (run) {
                    if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                        if (rxlen == 0) {
                            printf("Client closed connection\n");
                        }
                        ERR_print_errors_fp(stderr);
                        run=0;  
                    }
                    total_len+=rxlen;
                    num_ptks++;
                    if (num_ptks == 1) {
                        gettimeofday(&tv_first, NULL);
                    }
                    rxbuf[rxlen] = 0;
                    /* Look for kill switch */
                    if (strcmp(rxbuf, "kill\n") == 0) {
                        /* Terminate...with extreme prejudice */
                        printf("Server received 'kill' command\n");
                        run=0;
                    }
                }
            }
                gettimeofday(&tv_last, NULL);
                stats(&tv_first, &tv_last,num_ptks,total_len);
                num_ptks=0;
                total_len=0;          
}
   exit_s(ssl_ctx,ssl, client_skt,server_skt);
                                 
}
void client( struct sockaddr_in addr,SSL_CTX *ssl_ctx,SSL *ssl,char* buf,size_t len,char* rem_server_ip,int num_pk)
{

        printf("We are the client\n\n");
        configure_client_context(ssl_ctx);
        printf("contex set\n");
        int client_skt = create_socket(false);
         printf("client socket created\n");
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
        addr.sin_port = htons(server_port);
        printf("start connec to %s\n",rem_server_ip);
        int con=connect(client_skt, (struct sockaddr*) &addr, sizeof(addr));
        printf("%d\n",con);
        if (con!=0) {
            perror("Unable to TCP connect to server");
            goto exit;
        } else {
            printf("TCP connection to server successful\n");
        }
       ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        SSL_set_tlsext_host_name(ssl, rem_server_ip);
        /* Configure server hostname check */
        SSL_set1_host(ssl, rem_server_ip);
       
        /* Now do SSL connect with server */
        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");
            while (num_pk--) {
                
                if(num_pk==0)
                {
                    snprintf(buf,len,"kill\n");
                    printf("SENT KILL\n");   
                }
                int rec=SSL_write(ssl, buf, len);
                if (rec <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }
            }
            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }
    
exit:
        exit_s(ssl_ctx,ssl, client_skt,-1);

}
void exit_s(SSL_CTX *ssl_ctx,SSL *ssl,int client_skt,int server_skt){

 printf("Cleaning\n");
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        close(client_skt);
    if (server_skt != -1)
        close(server_skt);

}
double elapsed_time(struct timeval *tv_first, struct timeval *tv_end)
{
    double elapsed_msec;
    elapsed_msec = (tv_end->tv_sec - tv_first->tv_sec) * 1000;
    elapsed_msec += (tv_end->tv_usec - tv_first->tv_usec) / 1000;
    return elapsed_msec;
}

void stats(struct timeval *tv_first, struct timeval *tv_end,
        unsigned int numpkts_rx, unsigned int numbytes_rx)
{
 double elapsed_msec = elapsed_time(tv_first, tv_end);
   float MBps = numbytes_rx / ((elapsed_msec / 1000) * 1024*1024);
printf("packets received: %u \nbytes_received: %u \n"
               "average packets per second: %f \naverage Mega Bytes per second: %f (%f Mbps)\n"
               "duration (ms): %f \n",
               numpkts_rx, numbytes_rx, numpkts_rx / (elapsed_msec / 1000),
               MBps, MBps * 8, elapsed_msec);

}
void usage()
{
    printf("Usage: sslecho s\n");
    printf("       --or--\n");
    printf("       sslecho c ip\n");
    printf("       c=client, s=server, ip=dotted ip of server\n");
    exit(1);
}
