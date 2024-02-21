To-do:
- r4.cpp: Implement flow-based hashing, ECMP.
- r5.cpp: Implement single-thread `epoll`, reading packets from all ports
  (instead of port 0).
- r6.cpp: Implement multi-thead, accept-fork (one-process-per-connection)
  paradigm, assuming no shared data strucutre and no locks needed.
