#include <iostream>

#include "LeastConn.hpp"

void LeastConn::add_server(uint32_t ip, int port)
{
    LB_algo::add_server(ip, port);
    srv_conns.emplace(servers.back(), std::unordered_set<pid_t>());
    std::cout << "test:" << srv_conns.find(servers.back())->first.port << std::endl;
}

Server LeastConn::select_server(
    const struct sockaddr_in& client __attribute__((unused)))
{
    size_t least_num_conns = srv_conns.begin()->second.size();
    Server least_conn_server = srv_conns.begin()->first;
    std::cout << "first = " << least_conn_server.ip << ":" << least_conn_server.port << std::endl;

    for (const auto& srv_conn : srv_conns) {
        if (srv_conn.second.size() < least_num_conns) {
            least_num_conns = srv_conn.second.size();
            least_conn_server = srv_conn.first;
        }
    }

    std::cout << "selected = " << least_conn_server.ip << ":" << least_conn_server.port << std::endl;
    return least_conn_server;
}

void LeastConn::add_connection(pid_t pid, const Server& server)
{
    srv_conns[server].insert(pid);
    pid_to_srv[pid] = server;
}

void LeastConn::job_done(pid_t pid)
{
    srv_conns[pid_to_srv[pid]].erase(pid);
    pid_to_srv.erase(pid);
}
