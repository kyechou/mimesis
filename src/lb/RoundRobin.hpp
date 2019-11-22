#pragma once

#include "LB_algo.hpp"

class RoundRobin : public LB_algo
{
private:
    int cur_iter;

public:
    RoundRobin();

    Server select_server(const struct sockaddr_in& client) override;
};
