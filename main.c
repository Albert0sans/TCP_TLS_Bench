#include "header.h"
int main(int argc, char **argv)
{
    bool isServer;
    int num_pkts;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    struct sockaddr_in addr;
    char buf[BUFF_LEN] = "holaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    size_t len = sizeof(buf);
    char *rem_server_ip = NULL;
    printf("\nPerformance of TCP + TLS Based on OpenSSL demos : %s : %s\n\n", __DATE__,__TIME__);
    /* Need to know if client or server */
    if (argc < 2)
    {
        usage();
    }
    isServer = (argv[1][0] == 's') ? true : false;

    if (!isServer)
    {
        if (argc != 4)
        {
            usage();
        }
        rem_server_ip = argv[2];
        num_pkts=atoi(argv[3]);
    }
    /* Create context used by both client and server */
    ssl_ctx = create_context(isServer);

    /* If server */
    if (isServer)
    {
        server(ssl_ctx, ssl, buf, len);
    }
    /* Else client */
    else
    {
        client(addr, ssl_ctx, ssl, buf, len, rem_server_ip, num_pkts);
    }
    printf("sslecho exiting\n");
    return 0;
}