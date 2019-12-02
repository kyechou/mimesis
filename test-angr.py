#!/usr/bin/env python

import angr

visited_blocks = set()

def DFS_search(function, block):
    # TODO: search for the accept() call in block
    # if found, return the address and block
    if block in visited_blocks:
        return None
    visited_blocks.add(block)
    print(block)

    for successor in function.graph.successors(block):
        found = DFS_search(function, successor)
        if found:
            return found
    return None

# def main():
TARGET='lb'

p = angr.Project(TARGET, auto_load_libs=False)
cfg = p.analyses.CFGFast()
cg = cfg.functions.callgraph

#state = p.factory.entry_state()
#sm = p.factory.simulation_manager(state)
#sm.run(until=lambda sm_: len(sm_.active) > 1)

accepts = list()

for _, func in cfg.kb.functions.items():
    if func.name == 'accept':
        accepts.append(func)

parents = list()

for accept in accepts:
    for parent_addr in cg.predecessors(accept.addr):
        parent_func = cfg.kb.functions[parent_addr]
        if parent_func.name != 'accept':
            parents.append(parent_func)

# assuming there's only one piece of logic making the decision, which should
# be true under common circumstances
parent = parents[0]
visited_blocks.clear()
DFS_search(parent, parent.startpoint)

#if __name__ == '__main__':
#    main()
