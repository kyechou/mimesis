#include "SourceHash.hpp"

Server SourceHash::select_server(const struct sockaddr_in& client)
{
    uint32_t cli_addr = ntohl(client.sin_addr.s_addr);
    uint32_t cli_port = ntohs(client.sin_port);
    size_t choice = (cli_addr + cli_port) % servers.size();

    return servers[choice];
}
