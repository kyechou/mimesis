#pragma once

#include <unistd.h>
#include <cstdint>
#include <vector>

class Server
{
public:
    uint32_t ip;
    int port;

    Server() = default;
    Server(const Server&) = default;
    Server(Server&&) = default;
    Server(uint32_t ip, int port): ip(ip), port(port) {}

    Server& operator=(const Server&) = default;
    Server& operator=(Server&&) = default;
};

bool operator<(const Server&, const Server&);
bool operator==(const Server&, const Server&);

class LB_algo
{
protected:
    std::vector<Server> servers;

public:
    void add_server(uint32_t ip, int port);
    virtual Server select_server(const struct sockaddr_in& client) = 0;
    virtual void add_connection(pid_t pid, const Server& server);
    virtual void job_done(pid_t pid);
};
