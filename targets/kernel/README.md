### Demo Routers

To-do:
- r4.cpp: Implement flow-based hashing, ECMP.
- r5.cpp: Implement single-thread `epoll`, reading packets from all ports
  (instead of port 0).
- r6.cpp: Implement multi-thead, accept-fork (one-process-per-connection)
  paradigm, assuming no shared data strucutre and no locks needed.

### IP Routers

To-do:
- Add implementations of target programs for IP routers.
- r1.cpp: Implement simple IP-based routing, longest-prefix match, static route
  configuration.
- r2.cpp: Implement VLAN.
- r3.cpp: Implement VRF.
- r4.cpp: Implement tunneling and other types of header rewrites (VPN, NAT,
  virtualization).

### Firewalls

To-do:
- Add implementations of target programs for stateless and stateful firewalls.
- Implement stateless, IP-based firewall.
- Implement stateful, L4 firewall (TCP, UDP, ICMP).
