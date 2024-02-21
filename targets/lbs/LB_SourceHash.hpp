#pragma once

#include "LB_Algo.hpp"

class SourceHash : public LB_algo {
public:
    Server select_server(const struct sockaddr_in &client) override;
};
