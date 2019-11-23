#include <netinet/in.h>

#include "SourceHash.hpp"

Server SourceHash::select_server(const struct sockaddr_in& client)
{
    uint32_t hashed = (client.sin_addr.s_addr + (uint32_t)client.sin_port) % (uint32_t)servers.size();

    return servers.at(hashed);
}
