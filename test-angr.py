#!/usr/bin/env python

import angr

# def main():
TARGET='lb'

p = angr.Project(TARGET, auto_load_libs=False)
cfg = p.analyses.CFGFast()
cg = cfg.functions.callgraph

#state = p.factory.entry_state()
#sm = p.factory.simulation_manager(state)
#sm.run(until=lambda sm_: len(sm_.active) > 1)

accept = cfg.kb.functions['accept']
parents = list()

for parent_addr in cg.predecessors(accept.addr):
    parent_func = cfg.kb.functions[parent_addr]
    if parent_func.name != 'accept':
        parents.append(parent_func)

# assuming there's only one piece of logic making the decision, which should
# be true under common circumstances
parent = parents[0]
visited_nodes = set()

def DFS_search(project, function, node):
    # search for the accept() call in node (BlockNode)
    # if found, return the block and the instruction
    if node in visited_nodes:
        return None
    visited_nodes.add(node)
    block = project.factory.block(node.addr)
    for insn in block.capstone.insns:
        if insn.insn.insn_name() == 'call' and insn.op_str == hex(accept.addr):
            return (block, insn)

    for successor in function.graph.successors(node):
        found = DFS_search(project, function, successor)
        if found:
            return found
    return None

block, capstone_insn = DFS_search(p, parent, parent.startpoint)

#if __name__ == '__main__':
#    main()
