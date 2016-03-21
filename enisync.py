# Copyright 2016, Kai Groner <kai@gronr.com>
# Release under the simplified BSD license.  See LICENSE for details.

import argparse
from ipaddress import IPv4Interface
import re
from socket import AF_INET
import sys

import pyroute2
from pyroute2.netlink.rtnl import RTNLGRP_IPV4_IFADDR
from pyroute2.netlink.rtnl import RTNLGRP_LINK
from pyroute2.netlink.rtnl import RTNLGRP_IPV4_ROUTE


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
            '--interface', '-i', dest='if_pattern', metavar='PATTERN',
            default=r'eth\d+',
            help='Look for routes on interfaces matching PATTERN.')
    parser.add_argument(
            '--rule-priority-base', metavar='PRIORITY', type=int, default=1000,
            help='Generate rules starting at PRIORITY.')
    parser.add_argument(
            '--rt-table-base', metavar='TABLE', type=int, default=10000,
            help='Generate route tables starting at TABLE.')
    parser.add_argument(
            '--pdb', action='store_true',
            help='Enter pdb when it breaks.')

    subparsers = parser.add_subparsers(
            dest='command', metavar='COMMAND')
    once_parser = subparsers.add_parser('once',
            help='Create symmetric rules/routes, then exit.')
    monitor_parser = subparsers.add_parser('monitor',
            help='Create symmetric rules/routes continuously.')
    reset_parser = subparsers.add_parser('reset',
            help='Reset symmetric rules/routes.')
    parser.set_defaults(command='monitor')

    args = parser.parse_args()

    route_state_class = NLSymmetricRouteState
    if args.command == 'reset':
        route_state_class = NLResetSymmetricRouteState

    link_state = NLLinkState()
    route_state = route_state_class(
            link_state,
            if_pattern=args.if_pattern,
            rt_table_base=args.rt_table_base,
            rule_priority_base=args.rule_priority_base)

    def recv(msg):
        link_state.recv(msg)
        route_state.recv(msg)

    try:
        if args.command == 'monitor':
            monitor = pyroute2.IPRoute()
            monitor.bind(
                    RTNLGRP_LINK|RTNLGRP_IPV4_IFADDR|RTNLGRP_IPV4_ROUTE,
                    async=True)
            def forward_recv(msg):
                monitor.buffer_queue.put(msg.raw)
            real_recv, recv = recv, forward_recv

        with pyroute2.IPRoute() as ipr:
            for msg in ipr.get_links(): recv(msg)
            for msg in ipr.get_addr(AF_INET): recv(msg)
            for msg in ipr.get_routes(AF_INET): recv(msg)

        if args.command == 'monitor':
            try:
                while True:
                    for msg in monitor.get(): real_recv(msg)

            except KeyboardInterrupt:
                # This is how processes that run forever "normally exit".
                pass

    except Exception:
        if args.pdb:
            import pdb; pdb.post_mortem()
            exit(1)
        else:
            raise


class NLState:
    def recv(self, msg):
        event = msg['event']
        method = getattr(self, 'recv_{}'.format(event), None)
        if method is None:
            return
        attrs = dict(msg['attrs'])
        method(event, attrs, msg)


class NLLinkState(NLState):
    def __init__(self):
        self.links = {}

    def __getitem__(self, index):
        return self.links[index]

    def recv_RTM_NEWLINK(self, ev, attrs, msg):
        index = msg['index']
        ifname = attrs['IFLA_IFNAME']
        print('Adding link {} #{}'.format(ifname, index))
        if index not in self.links:
            self.links[index] = Link()
        self.links[index].update(name=ifname)

    def recv_RTM_DELLINK(self, ev, attrs, msg):
        index = msg['index']
        link = self.links[index]
        print('Dropping link {} #{}'.format(link.name, index))
        del self.links[index]

    def recv_RTM_NEWADDR(self, ev, attrs, msg):
        if msg['family'] != AF_INET: return
        index = msg['index']
        link = self.links[index]
        addr = IPv4Interface(
                '{}/{}'.format(attrs['IFA_ADDRESS'], msg['prefixlen']))
        print('Adding addr {} for {} #{}'.format(addr, link.name, index))
        link.addrs.add(addr)

    def recv_RTM_DELADDR(self, ev, attrs, msg):
        if msg['family'] != AF_INET: return
        index = msg['index']
        link = self.links[index]
        addr = IPv4Interface(
                '{}/{}'.format(attrs['IFA_ADDRESS'], msg['prefixlen']))
        print('Dropping addr {} for {} #{}'.format(addr, link.name, index))
        link.addrs.remove(addr)


class NLSymmetricRouteState(NLState):
    def __init__(self, links, *, if_pattern, rt_table_base, rule_priority_base):
        self.links = links
        self.if_pattern = if_pattern
        self.rt_table_base = rt_table_base
        self.rule_priority_base = rule_priority_base

    def recv_RTM_NEWROUTE(self, ev, attrs, msg):
        if msg['family'] != AF_INET: return
        # Ignore link local routes and other interfaces
        if msg['table'] != 254:
            return
        if_index = attrs['RTA_OIF']
        link = self.links[if_index]
        if not re.fullmatch(self.if_pattern, link.name):
            return

        # Look for default routes.
        if msg['dst_len'] > 0:
            return

        self.add_symmetric_route(attrs)

    def recv_RTM_DELROUTE(self, ev, attrs, msg):
        if msg['family'] != AF_INET: return
        # Ignore link local routes and other interfaces
        if msg['table'] != 254:
            return
        if_index = attrs['RTA_OIF']
        link = self.links[if_index]
        if not re.fullmatch(self.if_pattern, link.name):
            return

        # Look for default routes.
        if msg['dst_len'] > 0:
            return

        self.del_symmetric_route(attrs)

    def add_symmetric_route(self, attrs):
        if_index = attrs['RTA_OIF']
        link = self.links[if_index]
        priority = self.rule_priority_base + if_index
        table = self.rt_table_base + if_index
        addr = first(link.addrs)
        gw = attrs['RTA_GATEWAY']

        with pyroute2.IPRoute() as ipr:
            print('Checking for rules for default route for', link.name)
            if not ipr.get_rules(AF_INET, priority=priority):
                print('Setting up route/rule for', link.name, table, priority)

                ipr.rule('add',
                        priority=priority,
                        src=str(addr.network.network_address),
                        src_len=addr.network.prefixlen,
                        action='FR_ACT_TO_TBL',
                        table=table)

                ipr.route('add',
                        dst='0.0.0.0', mask=0,
                        gateway=gw,
                        oif=if_index,
                        prefsrc=str(addr.ip),
                        table=table)

    def del_symmetric_route(self, attrs):
        if_index = attrs['RTA_OIF']
        link = self.links[if_index]
        priority = self.rule_priority_base + if_index
        table = self.rt_table_base + if_index
        addr = first(link.addrs)
        gw = attrs['RTA_GATEWAY']

        with pyroute2.IPRoute() as ipr:
            print('Checking for rules for default route for', link.name)
            if ipr.get_rules(AF_INET, priority=priority):
                print('Tearing down route/rule for', link.name, table, priority)

                ipr.flush_rules(priority=priority)
                ipr.flush_routes(table=table)


class NLResetSymmetricRouteState(NLSymmetricRouteState):
    def recv_RTM_NEWROUTE(self, *a):
        super().recv_RTM_DELROUTE(*a)

    def recv_RTM_DELROUTE(self, *a):
        super().recv_RTM_NEWROUTE(*a)


class Link:
    def __init__(self, **kw):
        self.addrs = set()
        self.update(**kw)

    name = None

    def update(self, *, name=None):
        if name is not None:
            self.name = name


no_default = object()
def first(seq, *, default=no_default):
    for item in seq:
        return item
    if default is not no_default:
        return default
    raise ValueError


if __name__ == "__main__":
    main()
