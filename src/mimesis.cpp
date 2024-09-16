#include <boost/program_options.hpp>
#include <cassert>
#include <exception>
#include <filesystem>
#include <sstream>
#include <string>

#include "lib/logger.hpp"
#include "libps/manager.hpp"

namespace fs = std::filesystem;
namespace po = boost::program_options;

void parse_args(int argc, char **argv, fs::path &model_fp) {
    po::options_description desc("Mimesis (model client) options");
    desc.add_options()("help,h", "Show help message");
    desc.add_options()("model,m", po::value<std::string>()->default_value(""),
                       "Path to the extracted model file");
    desc.add_options()("query,q", po::value<std::string>()->default_value(""),
                       "Path to the input queries");
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

// void Mimesis::user_demo_stateless_queries(llvm::raw_ostream &os) const {
//     // user-demo-stateless: depth 1, pass, single-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr;
//         // (Eq 0x3
//         //     (ZExt w64 (Read w8 0x0 in_pkt_d1)))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0,
//         klee::Expr::Int32)); expr = klee::ZExtExpr::create(expr,
//         klee::Expr::Int64); expr =
//         klee::EqExpr::create(klee::ConstantExpr::create(3,
//         klee::Expr::Int64), expr); os << "Query constraint:\n" << expr <<
//         "\n"; os << "Timestamp: (queryStart) " + timestamp() + "\n"; auto res
//         = _model.query(1, expr); os << "Timestamp: (queryEnd) " + timestamp()
//         + "\n"; print_query_result(os, res); os <<
//         "=======================================================\n";
//     }
//
//     // user-demo-stateless: depth 1, drop, single-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr;
//         // (Eq 0xff
//         //     (ZExt w64 (Read w8 0x0 in_pkt_d1)))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0,
//         klee::Expr::Int32)); expr = klee::ZExtExpr::create(expr,
//         klee::Expr::Int64); expr =
//         klee::EqExpr::create(klee::ConstantExpr::create(0xff,
//         klee::Expr::Int64), expr); os << "Query constraint:\n" << expr <<
//         "\n"; os << "Timestamp: (queryStart) " + timestamp() + "\n"; auto res
//         = _model.query(1, expr); os << "Timestamp: (queryEnd) " + timestamp()
//         + "\n"; print_query_result(os, res); os <<
//         "=======================================================\n";
//     }
//
//     // user-demo-stateless: depth 1, pass & drop, symbolic multi-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr, n0;
//         // (And (Ule 0x3
//         //           N0: (ZExt w64 (Read w8 0x0 in_pkt_d1)))
//         //      (Uge 0xf
//         //           N0: (ZExt w64 (Read w8 0x0 in_pkt_d1))))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0,
//         klee::Expr::Int32)); n0 = klee::ZExtExpr::create(expr,
//         klee::Expr::Int64); expr =
//         klee::AndExpr::create(klee::UleExpr::create(klee::ConstantExpr::create(0x3,
//         klee::Expr::Int64), n0),
//                                      klee::UgeExpr::create(klee::ConstantExpr::create(0xf,
//                                      klee::Expr::Int64), n0));
//         os << "Query constraint:\n" << expr << "\n";
//         os << "Timestamp: (queryStart) " + timestamp() + "\n";
//         auto res = _model.query(1, expr);
//         os << "Timestamp: (queryEnd) " + timestamp() + "\n";
//         print_query_result(os, res);
//         os << "=======================================================\n";
//     }
// }

int main(int argc, char **argv) {
    fs::path model_fp;
    parse_args(argc, argv, model_fp);

    // Initialize and import the model.
    ps::Manager::get().init();
    info("Parsing model file: " + model_fp.string());
    ps::Model model = ps::Manager::get().import_model(model_fp);
    info("Parsed model file: " + model_fp.string());
    assert(model.validate());

    // TODO: Simplify model
    info(model.to_string());

    return 0;
}

// namespace {
//
// void print_query_result(llvm::raw_ostream &os, const
// std::set<std::shared_ptr<ps::TableEntry>> &result) {
//     std::function<void(llvm::raw_ostream &, const
//     std::shared_ptr<ps::TableEntry> &)> print_single_entry_rec;
//     print_single_entry_rec = [&print_single_entry_rec](llvm::raw_ostream &os,
//                                                        const
//                                                        std::shared_ptr<ps::TableEntry>
//                                                        &entry) -> void {
//         os << entry->to_string();
//         for (const auto &next : entry->next_entries()) {
//             print_single_entry_rec(os, next);
//         }
//     };
//
//     os << "---------  Query Result  ---------------------------\n";
//     for (const auto &entry : result) {
//         print_single_entry_rec(os, entry);
//     }
//     os << "----------------------------------------------------\n";
// }
//
// } // namespace

// void Mimesis::user_demo_stateful_queries(llvm::raw_ostream &os) const {
//     // user-demo-stateful: depth 1, drop, single-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_intf_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr;
//         // (Eq 0x3 (Read w8 0x0 in_intf_d1))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0,
//         klee::Expr::Int32)); expr =
//         klee::EqExpr::create(klee::ConstantExpr::create(0x3,
//         klee::Expr::Int8), expr); os << "Query constraint:\n" << expr <<
//         "\n"; os << "Timestamp: (queryStart) " + timestamp() + "\n"; auto res
//         = _model.query(1, expr); os << "Timestamp: (queryEnd) " + timestamp()
//         + "\n"; print_query_result(os, res); os <<
//         "=======================================================\n";
//     }
//
//     // user-demo-stateful: depth 2, pass -> pass, single-value
//     {
//         klee::ArrayPtr d1_array = klee::Array::create("in_intf_d1", 1);
//         klee::ArrayPtr d2_array = klee::Array::create("in_intf_d2", 1);
//         klee::UpdateListPtr d1_ul = klee::UpdateList::create(d1_array, 0);
//         klee::UpdateListPtr d2_ul = klee::UpdateList::create(d2_array, 0);
//         klee::ref<klee::Expr> expr, d1_expr, d2_expr;
//         // (And (Eq 0x0 (Read w8 0x0 in_intf_d1))
//         //      (Eq 0x5 (Read w8 0x0 in_intf_d2)))
//         d1_expr = klee::ReadExpr::create(d1_ul, klee::ConstantExpr::create(0,
//         klee::Expr::Int32)); d1_expr =
//         klee::EqExpr::create(klee::ConstantExpr::create(0, klee::Expr::Int8),
//         d1_expr); d2_expr = klee::ReadExpr::create(d2_ul,
//         klee::ConstantExpr::create(0, klee::Expr::Int32)); d2_expr =
//         klee::EqExpr::create(klee::ConstantExpr::create(5, klee::Expr::Int8),
//         d2_expr); expr = klee::AndExpr::create(d1_expr, d2_expr); os <<
//         "Query constraint:\n" << expr << "\n"; os << "Timestamp: (queryStart)
//         " + timestamp() + "\n"; auto res = _model.query(2, expr); os <<
//         "Timestamp: (queryEnd) " + timestamp() + "\n"; print_query_result(os,
//         res); os <<
//         "=======================================================\n";
//     }
// }
