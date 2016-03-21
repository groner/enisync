The enisync service maintains routing rules for multihomed systems.

It performs the same task as the ec2net or ec2utils packages, but it integrates
using the netlink interface.  This allows it to work with systemd networking,
which does not provide the scripting hooks needed to do this otherwise.
