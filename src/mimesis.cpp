#include <boost/program_options.hpp>
#include <cassert>
#include <exception>
#include <filesystem>
#include <iostream>
#include <klee/Constraints.h>
#include <klee/Expr.h>
#include <klee/Solver.h>
#include <ostream>
#include <sstream>
#include <string>

#include "lib/logger.hpp"
#include "lib/stats.hpp"
#include "libps/manager.hpp"

namespace fs = std::filesystem;
namespace po = boost::program_options;

void parse_args(int argc, char **argv, fs::path &model_fp) {
    po::options_description desc("Mimesis (model client) options");
    desc.add_options()("help,h", "Show help message");
    desc.add_options()("model,m", po::value<std::string>()->default_value(""),
                       "Path to the extracted model file");
    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const std::exception &e) {
        error(e.what());
    }

    if (vm.count("help")) {
        std::stringstream ss;
        ss << desc;
        info(ss.str());
        exit(0);
    }

    model_fp = vm.at("model").as<std::string>();
    if (model_fp.empty()) {
        error("Please specify a model file with --model");
    }
    if (!fs::exists(model_fp)) {
        error("File not found: " + model_fp.string());
    }
}

void print_query_result(
    std::ostream &os,
    const std::set<std::shared_ptr<ps::TableEntry>> &result) {
    std::function<void(std::ostream &, const std::shared_ptr<ps::TableEntry> &)>
        print_single_entry_rec;
    print_single_entry_rec =
        [&print_single_entry_rec](
            std::ostream &os,
            const std::shared_ptr<ps::TableEntry> &entry) -> void {
        os << entry->to_string();
        for (const auto &next : entry->next_entries()) {
            print_single_entry_rec(os, next);
        }
    };

    os << "---------  Query Result  ---------------------------\n";
    for (const auto &entry : result) {
        print_single_entry_rec(os, entry);
    }
    os << "----------------------------------------------------\n";
}

klee::ref<klee::Expr> user_demo_stateless_query(bool concrete_query) {
    if (concrete_query) {
        // user-demo-stateless: depth 1, pass, single-value
        klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
        klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
        klee::ref<klee::Expr> expr;
        // (Eq 0x3
        //     (ZExt w64 (Read w8 0x0 in_pkt_d1)))
        expr = klee::ReadExpr::create(
            ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
        expr = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        expr = klee::EqExpr::create(
            klee::ConstantExpr::create(3, klee::Expr::Int64), expr);
        return expr;
        // // user-demo-stateless: depth 1, drop, single-value
        // klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
        // klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
        // klee::ref<klee::Expr> expr;
        // // (Eq 0xff
        // //     (ZExt w64 (Read w8 0x0 in_pkt_d1)))
        // expr = klee::ReadExpr::create(
        //     ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
        // expr = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        // expr = klee::EqExpr::create(
        //     klee::ConstantExpr::create(0xff, klee::Expr::Int64), expr);
    } else {
        // user-demo-stateless: depth 1, pass & drop, symbolic multi-value
        klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
        klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
        klee::ref<klee::Expr> expr, n0;
        // (And (Ule 0x3
        //           N0: (ZExt w64 (Read w8 0x0 in_pkt_d1)))
        //      (Uge 0xf
        //           N0: (ZExt w64 (Read w8 0x0 in_pkt_d1))))
        expr = klee::ReadExpr::create(
            ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
        n0 = klee::ZExtExpr::create(expr, klee::Expr::Int64);
        expr = klee::AndExpr::create(
            klee::UleExpr::create(
                klee::ConstantExpr::create(0x3, klee::Expr::Int64), n0),
            klee::UgeExpr::create(
                klee::ConstantExpr::create(0xf, klee::Expr::Int64), n0));
        return expr;
    }
}

klee::ref<klee::Expr> user_demo_stateful_query(bool concrete_query) {
    if (concrete_query) {
        // user-demo-stateful: depth 1, drop, single-value
        klee::ArrayPtr array = klee::Array::create("in_intf_d1", 1);
        klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
        klee::ref<klee::Expr> expr;
        // (Eq 0x3 (Read w8 0x0 in_intf_d1))
        expr = klee::ReadExpr::create(
            ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
        expr = klee::EqExpr::create(
            klee::ConstantExpr::create(0x3, klee::Expr::Int8), expr);
        return expr;
    } else {
        // user-demo-stateful: depth 1, pass & drop, symbolic multi-value
        klee::ArrayPtr array = klee::Array::create("in_intf_d1", 1);
        klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
        klee::ref<klee::Expr> expr, n0;
        // (And (Ule 0x0
        //           N0: (Read w8 0x0 in_pkt_d1))
        //      (Uge 0xf
        //           N0: (Read w8 0x0 in_pkt_d1)))
        n0 = klee::ReadExpr::create(
            ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
        expr = klee::AndExpr::create(
            klee::UleExpr::create(
                klee::ConstantExpr::create(0x0, klee::Expr::Int8), n0),
            klee::UgeExpr::create(
                klee::ConstantExpr::create(0xf, klee::Expr::Int8), n0));
        return expr;
        // // user-demo-stateful: depth 2, pass -> pass, single-value
        // klee::ArrayPtr d1_array = klee::Array::create("in_intf_d1", 1);
        // klee::ArrayPtr d2_array = klee::Array::create("in_intf_d2", 1);
        // klee::UpdateListPtr d1_ul = klee::UpdateList::create(d1_array, 0);
        // klee::UpdateListPtr d2_ul = klee::UpdateList::create(d2_array, 0);
        // klee::ref<klee::Expr> expr, d1_expr, d2_expr;
        // // (And (Eq 0x0 (Read w8 0x0 in_intf_d1))
        // //      (Eq 0x5 (Read w8 0x0 in_intf_d2)))
        // d1_expr = klee::ReadExpr::create(
        //     d1_ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
        // d1_expr = klee::EqExpr::create(
        //     klee::ConstantExpr::create(0, klee::Expr::Int8), d1_expr);
        // d2_expr = klee::ReadExpr::create(
        //     d2_ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
        // d2_expr = klee::EqExpr::create(
        //     klee::ConstantExpr::create(5, klee::Expr::Int8), d2_expr);
        // expr = klee::AndExpr::create(d1_expr, d2_expr);
        // return expr;
    }
}

// klee::ref<klee::Expr> user_ip_stateful_query(bool concrete_query) {
//     if (concrete_query) {
//         // depth 1, pass, single-value
//         klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 0xe + 0x14);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr, sip;
//         // 0xc + 0x4 + 0x4;
//         // 0x10 + 0x4;
//         // (Read w8 0xc in_pkt_d1)
//     } else {
//         // user-demo-stateless: depth 1, pass & drop, symbolic multi-value
//     }
//     return {};
// }
// klee::ref<klee::Expr> user_ip_stateless_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> ebpf_demo_stateful_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> ebpf_demo_stateless_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> ebpf_ip_stateful_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> ebpf_ip_stateless_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> kernel_demo_stateful_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> kernel_demo_stateless_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> kernel_ip_stateful_query(bool concrete_query) {
//     return {};
// }
// klee::ref<klee::Expr> kernel_ip_stateless_query(bool concrete_query) {
//     return {};
// }

klee::ref<klee::Expr> general_query() {
    return klee::ConstantExpr::create(0x1, klee::Expr::Bool);
}

klee::ref<klee::Expr> get_query(const fs::path &model_fp, bool concrete_query) {
    std::string model_name = model_fp.stem().string();

    if (model_name.starts_with("user-demo-stateful")) {
        return user_demo_stateful_query(concrete_query);
    } else if (model_name.starts_with("user-demo-stateless")) {
        return user_demo_stateless_query(concrete_query);
        // } else if (model_name.starts_with("user-ip-stateful")) {
        //     return user_ip_stateful_query(concrete_query);
        // } else if (model_name.starts_with("user-ip-stateless")) {
        //     return user_ip_stateless_query(concrete_query);
        // } else if (model_name.starts_with("ebpf-demo-stateful")) {
        //     return ebpf_demo_stateful_query(concrete_query);
        // } else if (model_name.starts_with("ebpf-demo-stateless")) {
        //     return ebpf_demo_stateless_query(concrete_query);
        // } else if (model_name.starts_with("ebpf-ip-stateful")) {
        //     return ebpf_ip_stateful_query(concrete_query);
        // } else if (model_name.starts_with("ebpf-ip-stateless")) {
        //     return ebpf_ip_stateless_query(concrete_query);
        // } else if (model_name.starts_with("kernel-demo-stateful")) {
        //     return kernel_demo_stateful_query(concrete_query);
        // } else if (model_name.starts_with("kernel-demo-stateless")) {
        //     return kernel_demo_stateless_query(concrete_query);
        // } else if (model_name.starts_with("kernel-ip-stateful")) {
        //     return kernel_ip_stateful_query(concrete_query);
        // } else if (model_name.starts_with("kernel-ip-stateless")) {
        //     return kernel_ip_stateless_query(concrete_query);
    } else {
        return general_query();
        // error("Unknown model name: " + model_name);
        // return {};
    }
}

///// This may be helpful for comparing with SMT solving.
// klee::ConstraintManager constraints;
// constraints.addConstraint(expr);
// klee::Query q(constraints, _);

int main(int argc, char **argv) {
    fs::path model_fp;
    // std::ostream &os = std::cout;
    parse_args(argc, argv, model_fp);
    ps::Manager::get().init();
    _STATS_START(Stats::Op::ALL);

    // Initialize and import the model.
    // os << "Parsing model from " << model_fp << "...";
    _STATS_START(Stats::Op::MODEL_IMPORT);
    ps::Model model = ps::Manager::get().import_model(model_fp);
    _STATS_STOP(Stats::Op::MODEL_IMPORT);
    // os << " Done." << std::endl;

    // Validate the model.
    // model.validate();
    // info(model.to_string());

    std::set<std::shared_ptr<ps::TableEntry>> query_results;

    _STATS_START(Stats::Op::QUERY);
    query_results =
        model.query(/*max_depth=*/0, get_query(model_fp,
                                               /*concrete_query=*/false));
    _STATS_STOP(Stats::Op::QUERY);

    _STATS_STOP(Stats::Op::ALL);
    std::string model_name = model_fp.stem().string();
    _STATS_LOGRESULTS(model_name);
    return 0;
}
