# Linux ISG
This repo is fork of Linux ISG project from Oleg A. Arkhangelsky.

It is based on a non-original copy of source code recovered from old archive. Previously this code was published under GNU License so there is no problem to restore it in public.

# Changes
* Restore (write from scratch) match userspace library because it was lost during recovery
* Linux kernel version 4.19+ is supported

# TODO
* The code is really full of global spinlocks and currently do not scale well on multi-CPU servers. I will try to rewrite it with a new lockless techniques in future.
* A userspace daemon should be rewritten because perl is not fast enought in case of creating lots of new sessions per second.
* IPv6 support is fully absent. I think that shoud be fixed.

# Usage
## Session initiation and shaping
Use iptables to setup rules in `FORWARD` chain to specify how to init session
```bash
iptables -A FORWARD -s 192.0.0.0/24 -j ISG --init-session
iptables -A FORWARD -d 192.0.0.0/24 -j ISG
```
This commands will advise ISG module to initiate session for every IP address from 192.0.0.0/24 network and to policy traffic to 192.0.0.0/24 network in case of active session

## Redirect to authorization
```bash
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -m isg --service-name REDIRECT --j DNAT --to 192.0.0.1
```
This command will make DNAT for every HTTP packet that found in ISG with service REDIRECT. Possible usage to redirect to authorization web-site.

Additional documentation can be found by your favorite search engine
