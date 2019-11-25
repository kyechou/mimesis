#pragma once

#include <map>
#include <unordered_set>
#include <unordered_map>
#include "LB_algo.hpp"

class LeastConn : public LB_algo
{
private:
    std::map<Server, std::unordered_set<pid_t>> srv_conns;
    std::unordered_map<pid_t, Server> pid_to_srv;

public:
    void add_server(uint32_t ip, int port) override;
    Server select_server(const struct sockaddr_in& client) override;
    void add_connection(pid_t pid, const Server& server) override;
    void job_done(pid_t pid) override;
};
