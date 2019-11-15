#!/usr/bin/env python

import angr

TARGET='/usr/bin/wget'

proj = angr.Project(TARGET, auto_load_libs=False)
cfg = proj.analyses.CFGFast()
for func in list(proj.kb.functions.items()):
    print(func)
