#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

#include "LB_algo.hpp"
#include "RoundRobin.hpp"
#include "LeastConn.hpp"
#include "SourceHash.hpp"

LB_algo *lb;

void load_config(const std::string& cfg, LB_algo *&lb);
void reaper(int sig);
int passiveTCP(int port);
int proxy(const Server& server);

int main()
{
    std::string cfg = "src/lb.conf";
    int msock, ssock, port = 8088;
    pid_t childpid;
    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(struct sockaddr_in);

    load_config(cfg, lb);
    signal(SIGCHLD, reaper);

    /* build a TCP listening socket */
    if ((msock = passiveTCP(port)) < 0) {
        return EXIT_FAILURE;
    }

    while (1) {
        /* accept connection request */
        ssock = accept(msock, (struct sockaddr *)&cli_addr, &clilen);
        if (ssock < 0) {
            if (errno == EINTR) {
                return EXIT_SUCCESS;
            }
            std::cerr << "Error: accept failed" << std::endl;
            return EXIT_FAILURE;
        }

        Server server = lb->select_server(cli_addr);
        std::cout << "The selected server is " << server.ip << ":"
                  << server.port << std::endl;

        if ((childpid = fork()) < 0) {
            std::cerr << "Error: fork failed" << std::endl;
            return EXIT_FAILURE;
        } else if (childpid == 0) {
            // child
            dup2(ssock, STDIN_FILENO);
            dup2(ssock, STDOUT_FILENO);
            close(msock);
            close(ssock);
            return proxy(server);
        }

        lb->add_connection(childpid, server);
        close(ssock);
    }

    return EXIT_SUCCESS;
}

#define buflen 100000

int proxy(const Server& server)
{
    int srvfd, len;
    struct sockaddr_in srv_addr;
    char buffer[buflen] = {0};

    if ((srvfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Error: cannot open socket" << std::endl;
        return EXIT_FAILURE;
    }

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(server.ip);
    srv_addr.sin_port = htons(server.port);

    if (connect(srvfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        std::cerr << "Error: connect failed" << std::endl;
        return EXIT_FAILURE;
    }

    len = read(STDIN_FILENO, buffer, buflen);   // read request
    send(srvfd, buffer, len, 0);                // send request to server
    len = read(srvfd, buffer, buflen);          // read reply
    send(STDOUT_FILENO, buffer, len, 0);        // send reply to client

    close(srvfd);
    return EXIT_SUCCESS;
}

void reaper(int sig)
{
    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        lb->job_done(pid);
    }
    signal(sig, reaper);
}

static inline void usage(const std::string& progname)
{
    std::cout <<
              "Usage: " + progname + " [OPTIONS]\n"
              "Options:\n"
              "    -h, --help         print this help message\n"
              "    -f, --conf <file>  specify the configuration file (default: src/lb.conf)\n"
              "    -p, --port <port>  specify the listening port (default: 8088)\n";
}

static inline uint32_t strtoIP(const std::string& ips)
{
    int parsed, r, oct[4];
    r = sscanf(ips.c_str(), "%d.%d.%d.%d%n", oct, oct + 1, oct + 2, oct + 3,
               &parsed);
    if (r != 4 || parsed != (int)ips.size()) {
        std::cerr << "Failed to parse IP: " + ips << std::endl;
        exit(EXIT_FAILURE);
    }
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        if (oct[i] < 0 || oct[i] > 255) {
            std::cerr << "Invalid IP octet: " + std::to_string(oct[i])
                      << std::endl;
            exit(EXIT_FAILURE);
        }
        value = (value << 8) + oct[i];
    }
    return value;
}

void load_config(const std::string& cfg, LB_algo *&lb)
{
    std::string buf;
    std::ifstream config(cfg);

    if (config.fail()) {
        std::cerr << "Error: cannot open file: " + cfg << std::endl;
        exit(EXIT_FAILURE);
    }

    std::getline(config, buf);
    if (buf == "roundrobin") {
        lb = new RoundRobin();
    } else if (buf == "leastconn") {
        lb = new LeastConn();
    } else if (buf == "sourcehash") {
        lb = new SourceHash();
    } else {
        std::cerr << "Error: unknown algorithm: " + buf << std::endl;
        exit(EXIT_FAILURE);
    }

    while (std::getline(config, buf)) {
        size_t colon = buf.find(':');
        int port = std::stoi(std::string(buf, colon + 1));
        buf.erase(colon);
        lb->add_server(strtoIP(buf), port);
    }
}

int passiveTCP(int port)
{
    int sockfd;
    struct sockaddr_in serv_addr;

    /* open a TCP socket */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Error: cannot open socket" << std::endl;
        return -1;
    }

    /* allow reusing/binding to a port in TIME_WAIT */
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1) {
        std::cerr << "Error: setsockopt failed" << std::endl;
        return -1;
    }

    /* set up server socket addr */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    /* bind to server address */
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Error: failed to bind local address" << std::endl;
        return -1;
    }

    /* listen for requests */
    if (listen(sockfd, 0) < 0) {
        std::cerr << "Error: listen failed" << std::endl;
        return -1;
    }

    return sockfd;
}
