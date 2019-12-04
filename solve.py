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
parents = list()    # parent functions who call accept()

for parent_addr in cg.predecessors(accept.addr):
    parent_func = cfg.kb.functions[parent_addr]
    if parent_func.name != 'accept':
        parents.append(parent_func)

# assuming there's only one piece of logic making the decision, which should
# be true under common circumstances
parent = parents[0]

def is_call_accept(insn):
    return insn.insn.insn_name() == 'call' and insn.op_str == hex(accept.addr)

visited_nodes = set()
def DFS(project, function, node):
    # search for the accept() call in node (BlockNode)
    # if found, return the block and the instruction
    if node in visited_nodes:
        return None, None
    visited_nodes.add(node)
    block = project.factory.block(node.addr)
    for insn in block.capstone.insns:
        if is_call_accept(insn):
            return block, insn

    for successor in function.graph.successors(node):
        found = DFS(project, function, successor)
        if found[0] and found[1]:
            return found
    return None, None

accept_block, accept_insn = DFS(p, parent, parent.startpoint)
if not accept_block or not accept_insn:
    print('Error: cannot find "accept()" call in the program')
    sys.exit(1)


config = angr.SimFile(CONFIG_NAME, content=CONFIG_CONTENT, concrete=True)
blank_concrete_file = angr.SimFile('blank_concrete_file', content='',
        concrete=True)
state = p.factory.entry_state(addr=main.addr, args=[TARGET, '-f', CONFIG_NAME],
        fs={CONFIG_NAME: config}, stdin=blank_concrete_file)
sm = p.factory.simulation_manager(state)

## Find the state right before calling accept
sm.explore(find=accept_insn.insn.address)
s1 = sm.found[0]
cli_addr_ptr = s1.regs.rsi  # (struct sockaddr_in *)

## Find the state right after accept returns
sm.drop()
sm.move('found', 'active')
sm.explore(find=accept_insn.insn.address + accept_insn.insn.size)
s2 = sm.found[0]

# struct sockaddr_in {
#     short            sin_family;   // e.g. AF_INET
#     unsigned short   sin_port;     // e.g. htons(3490)
#     struct in_addr   sin_addr;     // see struct in_addr, below
#     char             sin_zero[8];  // zero this if you want to
# };
#
# struct in_addr {
#     unsigned long s_addr;  // load with inet_aton()
# };

s2.mem[cli_addr_ptr].short      = 2
s2.mem[cli_addr_ptr+2].uint16_t = 8000
s2.mem[cli_addr_ptr+4].uint32_t = 0xffffffff

#s3 = s2.step().successors[0]


decision_funcs = list()
for sym in p.loader.symbols:
    if sym.is_function and 'select_server' in sym.name:
        decision_funcs.append(cfg.kb.functions[sym.rebased_addr])


#state.inspect.b('call', when=angr.BP_BEFORE, function_name='accept', action=test)
#state.inspect.b('instruction', when=angr.BP_BEFORE, instruction=accept_insn.insn.address, action=test)

