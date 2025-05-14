#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdbool.h>
#include <pthread.h>

#define MAX_THREADS 128

typedef struct {
    const char *hostname;
    const char *port;
    const char *group_name;
    int repeat;
    FILE *csv_fp;
    pthread_mutex_t *csv_mutex;
    bool quiet;
} thread_data_t;

void *handshake_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;

    for (int i = 0; i < data->repeat; i++) {
        SSL_library_init();
        SSL_load_error_strings();

        const SSL_METHOD *method = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) continue;

        if (!SSL_CTX_set1_groups_list(ctx, data->group_name)) {
            SSL_CTX_free(ctx);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        BIO *conn = BIO_new_connect((char *)data->hostname);
        BIO_set_conn_port(conn, data->port);

        if (BIO_do_connect(conn) <= 0) {
            BIO_free_all(conn);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            continue;
        }

        SSL_set_bio(ssl, conn, conn);

        struct timeval start, end;
        gettimeofday(&start, NULL);

        if (SSL_connect(ssl) == 1) {
            gettimeofday(&end, NULL);
            double time_taken = (end.tv_sec - start.tv_sec) * 1000.0 +
                                (end.tv_usec - start.tv_usec) / 1000.0;

            if (!data->quiet) {
                if (data->csv_fp) {
                    pthread_mutex_lock(data->csv_mutex);
                    fprintf(data->csv_fp, "%.3f\n", time_taken);
                    pthread_mutex_unlock(data->csv_mutex);
                } else {
                    printf("%.3f\n", time_taken);
                }
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s <host> <port> <kem_group> [--repeat N] [--csv file.csv] [--threads T] [--quiet]\n", argv[0]);
        return 1;
    }

    const char *hostname = argv[1];
    const char *port = argv[2];
    const char *group_name = argv[3];
    int repeat = 1;
    const char *csv_file = NULL;
    int thread_count = 1;
    bool quiet = false;
    FILE *csv_fp = NULL;
    pthread_mutex_t csv_mutex;
    pthread_mutex_init(&csv_mutex, NULL);

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--repeat") == 0 && i + 1 < argc) {
            repeat = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv_file = argv[++i];
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            thread_count = atoi(argv[++i]);
            if (thread_count <= 0 || thread_count > MAX_THREADS) thread_count = 1;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            quiet = true;
        }
    }

    if (csv_file && !quiet) {
        csv_fp = fopen(csv_file, "w");
        if (!csv_fp) {
            fprintf(stderr, "Failed to open CSV file for writing\n");
            return 1;
        }
        fprintf(csv_fp, "handshake_ms\n");
    }

    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "oqsprovider");

    pthread_t threads[MAX_THREADS];
    thread_data_t thread_data[MAX_THREADS];
    int per_thread = repeat / thread_count;
    int extra = repeat % thread_count;

    for (int i = 0; i < thread_count; i++) {
        thread_data[i].hostname = hostname;
        thread_data[i].port = port;
        thread_data[i].group_name = group_name;
        thread_data[i].repeat = per_thread + (i < extra ? 1 : 0);
        thread_data[i].csv_fp = csv_fp;
        thread_data[i].csv_mutex = &csv_mutex;
        thread_data[i].quiet = quiet;
        pthread_create(&threads[i], NULL, handshake_thread, &thread_data[i]);
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    if (csv_fp) fclose(csv_fp);
    pthread_mutex_destroy(&csv_mutex);
    return 0;
}
