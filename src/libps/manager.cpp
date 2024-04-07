#include "libps/manager.hpp"

#include <cstdio>
#include <sylvan.h>
#include <sylvan_common.h>
#include <sylvan_obj.hpp>

// `third_party/sylvan/sylvan/examples/simple.cpp`:
//
// VOID_TASK_0(simple_cxx)
// {
//     Bdd one = Bdd::bddOne(); // the True terminal
//     Bdd zero = Bdd::bddZero(); // the False terminal
//
//     // check if they really are the True/False terminal
//     assert(one.GetBDD() == sylvan_true);
//     assert(zero.GetBDD() == sylvan_false);
//
//     Bdd a = Bdd::bddVar(0); // create a BDD variable x_0
//     Bdd b = Bdd::bddVar(1); // create a BDD variable x_1
//
//     // check if a really is the Boolean formula "x_0"
//     assert(!a.isConstant());
//     assert(a.TopVar() == 0);
//     assert(a.Then() == one);
//     assert(a.Else() == zero);
//
//     // check if b really is the Boolean formula "x_1"
//     assert(!b.isConstant());
//     assert(b.TopVar() == 1);
//     assert(b.Then() == one);
//     assert(b.Else() == zero);
//
//     // compute !a
//     Bdd not_a = !a;
//
//     // check if !!a is really a
//     assert((!not_a) == a);
//
//     // compute a * b and !(!a + !b) and check if they are equivalent
//     Bdd a_and_b = a * b;
//     Bdd not_not_a_or_not_b = !(!a + !b);
//     assert(a_and_b == not_not_a_or_not_b);
//
//     // perform some simple quantification and check the results
//     Bdd ex = a_and_b.ExistAbstract(a); // \exists a . a * b
//     assert(ex == b);
//     Bdd andabs = a.AndAbstract(b, a); // \exists a . a * b using AndAbstract
//     assert(ex == andabs);
//     Bdd univ = a_and_b.UnivAbstract(a); // \forall a . a * b
//     assert(univ == zero);
//
//     // alternative method to get the cube "ab" using bddCube
//     BddSet variables = a * b;
//     std::vector<unsigned char> vec = {1, 1};
//     assert(a_and_b == Bdd::bddCube(variables, vec));
//
//     // test the bddCube method for all combinations
//     assert((!a * !b) == Bdd::bddCube(variables, std::vector<uint8_t>({0,
//     0}))); assert((!a * b)  == Bdd::bddCube(variables,
//     std::vector<uint8_t>({0, 1}))); assert((!a)      ==
//     Bdd::bddCube(variables, std::vector<uint8_t>({0, 2}))); assert((a * !b)
//     == Bdd::bddCube(variables, std::vector<uint8_t>({1, 0}))); assert((a * b)
//     == Bdd::bddCube(variables, std::vector<uint8_t>({1, 1}))); assert((a) ==
//     Bdd::bddCube(variables, std::vector<uint8_t>({1, 2}))); assert((!b) ==
//     Bdd::bddCube(variables, std::vector<uint8_t>({2, 0}))); assert((b) ==
//     Bdd::bddCube(variables, std::vector<uint8_t>({2, 1}))); assert(one ==
//     Bdd::bddCube(variables, std::vector<uint8_t>({2, 2})));
// }

// Maybe useful functions:
//
// mtbdd_satcount(bdd, number_of_vars): compute the number of minterms
// (assignments that lead to True) for a function with <number_of_vars>
// variables; we don’t need to know the exact variables that may be in the BDD,
// just how many there are.
//
// sylvan_pathcount(bdd): compute the number of distinct paths to True.
//
// mtbdd_nodecount(bdd): compute the number of nodes (and leaves) in the BDD.
//
// mtbdd_nodecount_more(array, length): compute the number of nodes (and leaves)
// in the array of BDDs.

namespace ps {

using namespace sylvan;

Manager::Manager() {
    // The worker threads will busy-wait until a task is offered.
    lace_start(/*n_workers=*/1, /*dqsize=*/0);
    sylvan_set_limits(
        /*memory_cap=*/1UL * 1024 * 1024 * 1024, // 1 GB (value in bytes)
        /*table_ratio=*/1,  // Node table is twice (2^1) as big as the operation
                            // cache.
        /*initial_ratio=*/5 // The initial tables are 2^5 times smaller than the
                            // max size
    );
    sylvan_init_package();
    Sylvan::initBdd();
    lace_suspend();
}

Manager::~Manager() {
    lace_resume();
    sylvan_quit();
    lace_stop();
}

Manager &Manager::get() {
    static Manager instance;
    return instance;
}

void Manager::report_stats(FILE *out) {
    lace_resume();
    sylvan_stats_report(out);
    lace_suspend();
    if (fflush(out) != 0) {
        // TODO: error handling
    }
}

} // namespace ps
