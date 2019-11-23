#!/usr/bin/env python

import angr

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

#for block in main.blocks:
#    print("=======================")
#    block.pp()

#for s in cg.successors(main.addr):
#for s in cg.successors(p.entry):
#    succ_func = cfg.kb.functions[s]
#    if succ_func.name == 'accept':
#        pass

parents = list()

for accept in accepts:
    for parent_addr in cg.predecessors(accept.addr):
        parent_func = cfg.kb.functions[parent_addr]
        if parent_func.name != 'accept':
            parents.append(parent_func)

# assuming there's only one piece of logic making the decision
parent = parents[0]

for block in parent.blocks:
    print(block)
