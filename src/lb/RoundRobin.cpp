#include "RoundRobin.hpp"

RoundRobin::RoundRobin(): cur_iter(0)
{
}

Server RoundRobin::select_server(
    const struct sockaddr_in& client __attribute__((unused)))
{
    const Server& selected = servers[cur_iter];
    ++cur_iter;
    cur_iter %= SERVER_SIZE;
    return selected;
}
