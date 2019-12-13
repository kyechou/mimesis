#!/usr/bin/env python

import os
import sys
import logging
import argparse

################################################################################
# parse arguments
################################################################################

parser = argparse.ArgumentParser(description='Round robin experiment')
parser.add_argument('--input', dest='input', type=int)
parser.add_argument('--output-addr', dest='output_addr')
parser.add_argument('--output-port', dest='output_port', type=int)
parser.add_argument('--looping', dest='looping', action='store_true',
                    default=False)
arg = parser.parse_args()
if arg.output_addr:
    arg.output_addr = int(arg.output_addr, 16)

################################################################################

import angr

os.chdir(os.path.dirname(os.path.realpath(__file__)))
logging.getLogger('angr').setLevel('ERROR')

TARGET = 'lb'

p = angr.Project(TARGET, auto_load_libs=False)
cfg = p.analyses.CFGFast()
cg = cfg.functions.callgraph

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

#fork = cfg.kb.functions['fork']
#fork_parents = list()    # parent functions who call fork()
#
#for parent_addr in cg.predecessors(fork.addr):
#    parent_func = cfg.kb.functions[parent_addr]
#    if parent_func.name != 'fork':
#        fork_parents.append(parent_func)
#
#fork_parent = fork_parents[0]
#
#def is_call_fork(insn):
#    return insn.insn.insn_name() == 'call' and insn.op_str == hex(fork.addr)
#fork_insn = find_instruction(p, acc_parent, is_call_fork)
#if not fork_insn:
#    print('Error: cannot find "fork()" call in the program')
#    sys.exit(1)

################################################################################

decision_funcs = list()
for sym in p.loader.symbols:
    if sym.is_function and 'select_server' in sym.name:
        decision_funcs.append(cfg.kb.functions[sym.rebased_addr])

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

blank_concrete_file = angr.SimFile('blank_concrete_file', content='',
        concrete=True)
main = cfg.kb.functions['main']
state = p.factory.entry_state(addr=main.addr, stdin=blank_concrete_file)
sm = p.factory.simulation_manager(state)

# Find the state right before calling accept
sm.explore(find=accept_insn.insn.address)
s1 = sm.found[0]
sm.drop()
sm.move('found', 'active')
cli_addr_ptr = s1.regs.rsi  # (struct sockaddr_in *)

# Find the state right after accept returns
sm.explore(find=accept_insn.insn.address + accept_insn.insn.size)
s2 = sm.found[0]
sm.drop()
sm.move('found', 'active')

# Set the client address and port, which would not affect the result no matter
# what, because roundrobin does not depend on the information.
#
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
#cli_port = s2.solver.BVS("cli_port", 16)
#cli_ip = s2.solver.BVS("cli_ip", 32)
#s2.solver.add(cli_ip == 0x7f000001)
#s2.solver.add(cli_port > 1024)
#s2.mem[cli_addr_ptr+2].uint16_t = cli_port
#s2.mem[cli_addr_ptr+4].uint32_t = cli_ip

################################################################################
# RoundRobin
################################################################################

# Find the state right before calling select_server
sm.explore(find=decision_insn.insn.address)
s3 = sm.found[0]
sm.drop()
sm.move('found', 'active')

# round robin iterator
if not arg.looping:
    rr_this = s3.regs.rdi
    cur_iter_ptr = rr_this + 8
    if arg.input != None:
        cur_iter = s3.solver.BVV(arg.input, 32)
    else:
        cur_iter = s3.solver.BVS("cur_iter", 32)
    s3.solver.add(cur_iter >= 0)
    s3.solver.add(cur_iter < 4)
    s3.mem[cur_iter_ptr].int = cur_iter

# Find the state right after select_server returns
sm.explore(find=decision_insn.insn.address + decision_insn.insn.size)
s4 = sm.found[0]
sm.drop()
sm.move('found', 'active')


if arg.looping:
    def bp_action(state):
        print('================ RoundRobin ================')
        addr = state.regs.rax & state.solver.BVV(0xffffffff, 64)
        port = (state.regs.rax & state.solver.BVV(0xffffffff00000000, 64)) >> 32
        print('Addr:', addr)
        print('Port:', port)
        print('Evaluated addr:', hex(s4.solver.eval(addr)))
        print('Evaluated port:', s4.solver.eval(port))
    bp = s4.inspect.b('instruction',
            instruction=decision_insn.insn.address + decision_insn.insn.size,
            action=bp_action)
    sm.run()
else:
    print('================ RoundRobin ================')
    addr = s4.regs.rax & s4.solver.BVV(0xffffffff, 64)
    port = (s4.regs.rax & s4.solver.BVV(0xffffffff00000000, 64)) >> 32
    if arg.output_addr != None:
        s4.solver.add(addr == arg.output_addr)
    if arg.output_port != None:
        s4.solver.add(port == arg.output_port)
    print('cur_iter:', cur_iter)
    print('Addr:', addr)
    print('Port:', port)
    print('Evaluated cur_iter:', s4.solver.eval(cur_iter))
    print('Evaluated addr:', hex(s4.solver.eval(addr)))
    print('Evaluated port:', s4.solver.eval(port))
