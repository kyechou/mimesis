#!/usr/bin/env python

import os
import sys
import argparse

################################################################################
# parse arguments
################################################################################

parser = argparse.ArgumentParser(description='HAProxy experiment')
parser.add_argument('--target', dest='target')
arg = parser.parse_args()

################################################################################

import angr

os.chdir(os.path.dirname(os.path.realpath(__file__)))

if arg.target != None:
    TARGET = arg.target
else:
    TARGET = 'haproxy-1.5.0'

p = angr.Project(TARGET, auto_load_libs=False)
cfg = p.analyses.CFGFast()
cg = cfg.functions.callgraph

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
        return None, None
    visited_nodes.add(node)
    block = project.factory.block(node.addr)
    for insn in block.capstone.insns:
        if insn.insn.insn_name() == 'call' and insn.op_str == hex(accept.addr):
            return block, insn

    for successor in function.graph.successors(node):
        found = DFS_search(project, function, successor)
        if found[0] and found[1]:
            return found
    return None, None

block, capstone_insn = DFS_search(p, parent, parent.startpoint)
if not block or not capstone_insn:
    print('Error: cannot find "accept()" call in the program')
    sys.exit(1)

state = p.factory.entry_state(args=[TARGET, '-Ws',
                                    '-f', '/etc/haproxy/haproxy.cfg',
                                    '-p', '/run/haproxy.pid',
                                    '-S', '/run/haproxy-master.sock'])
sm = p.factory.simulation_manager(state)
sm.explore(find=capstone_insn.insn.address)
print('Simulation manager:', sm)
print('SimMgr.found stash:', sm.found)