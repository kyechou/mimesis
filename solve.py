#!/usr/bin/env python

import os
import sys
import angr

#os.chdir(os.path.dirname(os.path.realpath(__file__)))

TARGET = 'lb'
CONFIG_NAME = 'src/lb.conf'
CONFIG_CONTENT = '''leastconn
127.0.0.1:9000
127.0.0.1:9001
127.0.0.1:9002
127.0.0.1:9003
'''

p = angr.Project(TARGET, auto_load_libs=False)
cfg = p.analyses.CFGFast()
cg = cfg.functions.callgraph

main = cfg.kb.functions['main']
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


config = angr.SimFile(CONFIG_NAME, content=CONFIG_CONTENT, concrete=True)
blank_concrete_file = angr.SimFile('blank_concrete_file', content='',
        concrete=True)
state = p.factory.entry_state(addr=main.addr, args=[TARGET, '-f', CONFIG_NAME],
        fs={CONFIG_NAME: config}, stdin=blank_concrete_file)
sm = p.factory.simulation_manager(state)

# def tmp(sm_):
#    if len(sm_.active) > 1:
#        print('======= Braching =======')
#        return True
#    for s in sm_.active:
#        ip = s.solver.eval(s.ip)
#        if ip >= 0x4036c6 and ip <= 0x403729:
#            print('======= ~ LOAD_CONFIG =======')
#            print('IP:', s.ip)
#            return True
#        #elif ip >= 0x403e16 and ip <= 0x40425b:
#        #    print('======= LOAD_CONFIG =======')
#        #    print('IP:', s.ip)
#        #    return True
#        elif ip >= 0x403729 and ip <= capstone_insn.insn.address:
#            print('======= LOAD_CONFIG ~ ACCEPT =======')
#            print('IP:', s.ip)
#            return True
#        #elif ip >= block.addr and ip <= capstone_insn.insn.address:
#        #    print('======= ACCEPT BLOCK =======')
#        #    print('IP:', s.ip)
#        #    return True
#    return False
#sm.run(until=tmp)
#sm.run(until=tmp)
#sm.run(until=tmp)
#sm.run(until=tmp)

sm.explore(find=capstone_insn.insn.address)

#s = state.step()
#while len(s.successors) == 1:
#    s = s.successors[0].step()

#state.inspect.b('call', when=angr.BP_BEFORE, function_name='accept', action=test)
#state.inspect.b('instruction', when=angr.BP_BEFORE, instruction=capstone_insn.insn.address, action=test)

#sm.explore(find=lambda s: s.solver.eval(s.regs.rdi) == capstone_insn.insn.address)
#sm.run(until=lambda sm_: len(sm_.active) > 1)
