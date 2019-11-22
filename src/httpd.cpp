#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <cctype>

static inline bool arespace (const std::string&);
static inline std::string ip_to_str(uint32_t);

class Request   // HTTP request
{
private:
    std::string method;
    std::string path;
    std::string qstring;
    std::string proto;
    std::string host;
    std::string port;

public:
    std::string get_proto() const
    {
        return proto;
    }

    std::string get_host() const
    {
        return host;
    }

    std::string get_port() const
    {
        return port;
    }

    void read(std::istream& is)
    {
        std::string buf, key, value;
        std::getline(is, buf);
        std::stringstream bufss(buf);

        /* method */
        bufss >> method;
        /* path & query string */
        bufss >> path;
        size_t q = path.find('?');
        if (q != path.npos) {
            qstring = std::string(path, q + 1);
            path.erase(q);
        }
        /* HTTP protocol */
        bufss >> proto;

        /* read through each line of the request header */
        while (std::getline(is, buf) && !arespace(buf)) {
            /* setting up the key value pair */
            key = buf;
            size_t v = buf.find(':');
            if (v != buf.npos) {
                key.erase(v);
                do {
                    ++v;
                } while (v < buf.size() && isspace(buf[v]));
                value = std::string(buf, v);
            } else {
                value.clear();
            }

            /* set up the value you're interested in */
            if (key == "Host") {
                /* seperate the hostname and port number */
                size_t sep = value.find(':');
                if (sep != value.npos) {
                    port = std::string(value, sep + 1);
                    value.erase(sep);
                } else {
                    port.clear();
                }
                host = value;
            }
        }
    }
};

int httpd(const std::string& server_name, const struct sockaddr_in& cli_addr)
{
    Request req;
    req.read(std::cin);

    std::string payload =
        "<!DOCTYPE html>\n"
        "<html>"
        "<head><title>" + server_name + "</title></head>"
        "<body>"
        "<h1>" + server_name + "</h1>"
        "<h3>Request</h3>"
        "<p>"
        "From: " + ip_to_str(ntohl(cli_addr.sin_addr.s_addr)) +
        ":" + std::to_string(ntohs(cli_addr.sin_port)) + "</br>"
        "To: " + req.get_host() + ":" + req.get_port() +
        "</p>"
        "<h3>Reply</h3>"
        "<p>"
        "From: " + req.get_host() + ":" + req.get_port() + "</br>"
        "To: " + ip_to_str(ntohl(cli_addr.sin_addr.s_addr)) +
        ":" + std::to_string(ntohs(cli_addr.sin_port)) +
        "</p>"
        "</body>"
        "</html>\n";
    std::string output =
        req.get_proto() + " 200 OK\n"
        "Server: sake\n"
        "Content-Type: text/html\n"
        "Content-Length: " + std::to_string(payload.size()) + "\n"
        "\n" + payload;

    write(STDOUT_FILENO, output.c_str(), output.size());
    return 0;
}

static inline std::string ip_to_str(uint32_t ip)
{
    return std::to_string((ip >> 24) & 255) + "." +
           std::to_string((ip >> 16) & 255) + "." +
           std::to_string((ip >>  8) & 255) + "." +
           std::to_string((ip      ) & 255);
}

static inline bool arespace (const std::string& s)
{
    for (char c : s) {
        if (!isspace(c)) {
            return false;
        }
    }
    return true; /* empty strings are treated as spaces */
}


void parse_args(int argc, char **argv, std::string& server_name, int& port);
void reaper(int sig);
int passiveTCP(int port);

int main(int argc, char **argv)
{
    std::string server_name;
    int msock, ssock, port;
    pid_t childpid;
    socklen_t clilen = sizeof(struct sockaddr_in);
    struct sockaddr_in cli_addr;

    parse_args(argc, argv, server_name, port);
    signal(SIGCHLD, reaper);    // signal handler for SIGCHLD

    /* build a TCP listening socket */
    if ((msock = passiveTCP(port)) < 0) {
        return -1;
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

        /* fork another process to handle the request */
        if ((childpid = fork()) < 0) {
            std::cerr << "Error: fork failed" << std::endl;
            return EXIT_FAILURE;
        } else if (childpid == 0) {
            // child
            dup2(ssock, STDIN_FILENO);
            dup2(ssock, STDOUT_FILENO);
            close(msock);
            close(ssock);
            exit(httpd(server_name, cli_addr));
        }
        close(ssock);
    }

    return EXIT_SUCCESS;
}

static inline void usage(const std::string& progname)
{
    std::cout <<
              "Usage: " + progname + " [-h] -n <name> -p <port>\n"
              "    -h, --help             print this help message\n"
              "    -n, --name <name>      specify server name\n"
              "    -p, --port <port>      specify port number\n";
}

void parse_args(int argc, char **argv, std::string& server_name, int& port)
{
    int opt;
    const char *optstring = "hn:p:";
    const struct option longopts[] = {
        {"help",    no_argument,       0, 'h'},
        {"name",    required_argument, 0, 'n'},
        {"port",    required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    server_name.clear();
    port = 0;

    while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'n':
                server_name = optarg;
                break;
            case 'p':
                port = strtol(optarg, NULL, 10);
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    bool invalid = false;

    if (server_name.empty()) {
        std::cerr << "Error: missing server name" << std::endl;
        invalid = true;
    }
    if (port == 0) {
        std::cerr << "Error: missing port" << std::endl;
        invalid = true;
    }

    if (invalid) {
        std::cerr << "Try '" << argv[0] << " -h' for more information"
                  << std::endl;
        exit(EXIT_FAILURE);
    }
}

void reaper(int sig)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
    signal(sig, reaper);
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
