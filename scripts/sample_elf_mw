#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

void create_flag_file() {
    char home_path[1024];
    strcpy(home_path, getenv("HOME"));
    strcat(home_path, "/Hacking Test");

    FILE *file = fopen(home_path, "w");
    if (file == NULL) {
        perror("Error creating file");
        return;
    }

    fprintf(file, "This is just a test.");
    fclose(file);
}

void make_connection() {
    int sock;
    struct sockaddr_in server;
    struct hostent *host;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Could not create socket");
        return;
    }

    host = gethostbyname("justplayingaroungwithacode.abc");
    if (host == NULL) {
        perror("gethostbyname() error");
        return;
    }

    server.sin_addr = *((struct in_addr*)host->h_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection error");
    } else {
        printf("Connected successfully (this is just a test, no actual data was sent or received)\n");
    }

    close(sock);
}

int main() {
    create_flag_file();
    make_connection();
    return 0;
}
