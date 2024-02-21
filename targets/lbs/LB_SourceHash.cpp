#include "LB_SourceHash.hpp"

Server SourceHash::select_server(const struct sockaddr_in &client) {
    uint32_t cli_addr = (client.sin_addr.s_addr);
    uint32_t cli_port = (client.sin_port);
    size_t choice = (cli_addr + cli_port) % SERVER_SIZE;

    return servers[choice];
}
