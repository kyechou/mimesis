#include <cstdint>
#include <gtest/gtest.h>
#include <klee/Common.h>
#include <klee/Expr.h>
#include <klee/util/Ref.h>
#include <linux/if_ether.h>
#include <llvm/Support/raw_ostream.h>
#include <string>
#include <unistd.h>

#include "libps/manager.hpp"

struct DemoHeader {
    uint16_t seed; // egress port
    uint16_t len;  // payload length
};

class PacketSetTests : public testing::Test {
protected:
    llvm::raw_ostream *out = nullptr;
    const std::string var_name = "ingress_packet";
    klee::ArrayPtr array;
    klee::UpdateListPtr ul;

    void SetUp() override {
        // Output streams
        out = new llvm::raw_fd_ostream(/*fd=*/STDOUT_FILENO,
                                       /*shouldClose=*/false);
        klee::klee_message_stream = out;
        klee::klee_warning_stream = out;

        // Initialize libps
        ps::Manager::get().init(/*n_workers=*/1,
                                /*memory_cap=*/1UL * 1024 * 1024 * 1024,
                                /*table_ratio=*/1,
                                /*initial_ratio=*/5);

        // Create symbolic variable
        auto hdr_len = sizeof(struct ethhdr) + sizeof(struct DemoHeader);
        array = klee::Array::create(var_name, hdr_len);
        ul = klee::UpdateList::create(array, 0);
        ps::Manager::get().register_symbolic_variable(var_name, hdr_len * 8);
    }

    void TearDown() override {
        // Output streams
        delete out;
        out = nullptr;
        klee::klee_message_stream = nullptr;
        klee::klee_warning_stream = nullptr;
        // libps
        ps::Manager::get().reset();
    }
};
