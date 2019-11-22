#include "LB_algo.hpp"

bool operator<(const Server& a, const Server& b)
{
    if (a.ip < b.ip) {
        return true;
    } else if (a.ip > b.ip) {
        return false;
    }
    if (a.port < b.port) {
        return true;
    }
    return false;
}

bool operator==(const Server& a, const Server& b)
{
    if (a.ip == b.ip && a.port == b.port) {
        return true;
    }
    return false;
}

void LB_algo::add_server(uint32_t ip, int port)
{
    servers.push_back(Server(ip, port));
}

void LB_algo::add_connection(pid_t pid __attribute__((unused)),
                    const Server& server __attribute__((unused)))
{
}

void LB_algo::job_done(pid_t pid __attribute__((unused)))
{
}
