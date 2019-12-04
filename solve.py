#!/usr/bin/env python

import os
import sys
import angr

################################################################################

def inorder_DFS(p, parent_func, find, find_all):
    visited_nodes = set()
    insns = set()
    def DFS_internal(p, function, find, find_all, node):
        # Search for the instruction in node (BlockNode) such that find(insn) is
        # True. If found, return the instruction.
        if node in visited_nodes:
            return None
        visited_nodes.add(node)
        block = p.factory.block(node.addr)
        for insn in block.capstone.insns:
            if find(insn):
                if not find_all:
                    return insn
                else:
                    insns.add(insn)

        for successor in function.graph.successors(node):
            found = DFS_internal(p, function, find, find_all, successor)
            if not find_all and found:
                return found
        return insns
    return DFS_internal(p, parent_func, find, find_all, parent_func.startpoint)

def find_instruction(p, parent_func, find, find_all=False):
    return inorder_DFS(p, parent_func, find, find_all)


################################################################################

#os.chdir(os.path.dirname(os.path.realpath(__file__)))

TARGET = 'lb'
CONFIG_NAME = 'src/lb.conf'
CONFIG_CONTENT = '''sourcehash
127.0.0.1:9000
127.0.0.1:9001
127.0.0.1:9002
127.0.0.1:9003
'''

p = angr.Project(TARGET, auto_load_libs=False)
cfg = p.analyses.CFGFast()
cg = cfg.functions.callgraph

################################################################################

accept = cfg.kb.functions['accept']
acc_parents = list()    # parent functions who call accept()

for parent_addr in cg.predecessors(accept.addr):
    parent_func = cfg.kb.functions[parent_addr]
    if parent_func.name != 'accept':
        acc_parents.append(parent_func)

# assuming there's only one piece of logic making the decision, which should
# be true under common circumstances
acc_parent = acc_parents[0]

def is_call_accept(insn):
    return insn.insn.insn_name() == 'call' and insn.op_str == hex(accept.addr)
accept_insn = find_instruction(p, acc_parent, is_call_accept)
if not accept_insn:
    print('Error: cannot find "accept()" call in the program')
    sys.exit(1)

################################################################################

fork = cfg.kb.functions['fork']
fork_parents = list()    # parent functions who call fork()

for parent_addr in cg.predecessors(fork.addr):
    parent_func = cfg.kb.functions[parent_addr]
    if parent_func.name != 'fork':
        fork_parents.append(parent_func)

fork_parent = fork_parents[0]

def is_call_fork(insn):
    return insn.insn.insn_name() == 'call' and insn.op_str == hex(fork.addr)
fork_insn = find_instruction(p, acc_parent, is_call_fork)
if not fork_insn:
    print('Error: cannot find "fork()" call in the program')
    sys.exit(1)

################################################################################

config = angr.SimFile(CONFIG_NAME, content=CONFIG_CONTENT, concrete=True)
blank_concrete_file = angr.SimFile('blank_concrete_file', content='',
        concrete=True)
main = cfg.kb.functions['main']
state = p.factory.entry_state(addr=main.addr, args=[TARGET, '-f', CONFIG_NAME],
        fs={CONFIG_NAME: config}, stdin=blank_concrete_file)
sm = p.factory.simulation_manager(state)

## Find the state right before calling accept
sm.explore(find=accept_insn.insn.address)
s1 = sm.found[0]
sm.drop()
sm.move('found', 'active')
cli_addr_ptr = s1.regs.rsi  # (struct sockaddr_in *)

## Find the state right after accept returns
sm.explore(find=accept_insn.insn.address + accept_insn.insn.size)
s2 = sm.found[0]
sm.drop()
sm.move('found', 'active')

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
s2.mem[cli_addr_ptr+2].uint16_t = 12345
s2.mem[cli_addr_ptr+4].uint32_t = 0x7f000001    # 127.0.0.1

################################################################################

# def reading_cli_addr(insn):
#    if insn.insn.insn_name() == 'mov':
#        print(insn)
#    return insn.insn.insn_name() == 'mov'

decision_funcs = list()
for sym in p.loader.symbols:
    if sym.is_function and 'select_server' in sym.name:
        decision_funcs.append(cfg.kb.functions[sym.rebased_addr])
#read_cli_insns = set()
#for f in decision_funcs:
#    insns = find_instruction(p, f, reading_cli_addr, find_all=True)
#    if insns:
#        read_cli_insns.update(insns)

################################################################################

decision_parents = set()    # parent functions who call select_server()

for dec_f in decision_funcs:
    for parent_addr in cg.predecessors(dec_f.addr):
        parent_func = cfg.kb.functions[parent_addr]
        if 'select_server' not in parent_func.name:
            decision_parents.add(parent_func)

def is_call_decision(insn):
    return insn.insn.insn_name() == 'call' and (
            insn.op_str in [hex(f.addr) for f in decision_funcs])
decision_insns = set()
for dec_parent in decision_parents:
    insns = find_instruction(p, dec_parent, is_call_decision, find_all=True)
    decision_insns.update(insns)
if not decision_insns:
    print('Error: cannot find "select_server()" call in the program')
    sys.exit(1)
decision_insn = list(decision_insns)[0]

################################################################################

## Find the state right before calling select_server
sm.explore(find=decision_insn.insn.address)
s3 = sm.found[0]
sm.drop()
sm.move('found', 'active')

## Find the state right after select_server returns
sm.explore(find=decision_insn.insn.address + decision_insn.insn.size)
s4 = sm.found[0]
sm.drop()
sm.move('found', 'active')

################################################################################

# def bp_action(state):
#    print('============ BREAKPOINT ============')
#    print('IP:', state.ip)
#    print('&cli_addr:', cli_addr_ptr)
#    print('MEM READ:', state.inspect.mem_read_address)
#    print('MEM RD LEN:', state.inspect.mem_read_length)
#bp = s4.inspect.b('mem_read', mem_read_address=cli_addr_ptr+2, action=bp_action)
#bp = s4.inspect.b('mem_read', mem_read_address=cli_addr_ptr+4, action=bp_action)
#sm.explore(find=fork_insn.insn.address)

################################################################################
# SourceHash
################################################################################
