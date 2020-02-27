#!/usr/bin/python

"""
This example shows how to create a simple network like this:
               VNF
               |
               |
               |
               |
    d1---------SFF---------d2

    [C0]

    ,where:
    d1, d2 - docker containers (perform as hosts)
    [C0] - Controller
    SFF - Service Function Forwarder (just OVSSwitch right now)
    VNF - Virtual Network Function (an arbitrary virtual function that somehow handles traffic)
"""

from mininet.net import Containernet
from mininet.node import Controller, Docker, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Link


def topology():
    """Create a network with some docker containers acting as hosts.
    """

    net = Containernet(controller=Controller)

    # info('*** Adding controller\n')
    # net.addController('c0')

    info('*** Adding docker containers (as hosts)\n')
    dh1, dh2 = [net.addHost(f"dh{i}", ip=f'11.0.0.{i}', cls=Docker,
                            dimage='vityaszv/custom_container:latest', cpu_shares=20) for i in range(1, 3)]
    amount_of_hosts = 2
    info('*** Adding SFF\n')
    sff = net.addServiceFunctionForwarder('s1', cls=OVSSwitch)


    info('*** Creating links\n')

    for el in [dh1, dh2]:
        net.addLink(el, sff)

    info('*** Adding VNF\n')
    vnf = net.addVirtualNetworkFunction('v1', dimage="vityaszv/custom_container:latest", switch=sff)


    info('*** Starting network\n')
    net.start()

    # adding flows for redirecting traffic from dh1 dh2 to v1
    for i in [dh1, dh2]:
        print(sff.dpctl("add-flow", "priority=100,icmp,nw_src=11.0.0.0/24,actions=output:3"))

    # adding flows for transferring traffic from v1 to dh1 and dh2
    print(dh1.IP())
    print(sff.dpctl("add-flow", "arp,actions=normal"))
    print(sff.dpctl("add-flow", f"priority=100,icmp,in_port=3,nw_dst=11.0.0.1,actions=output:1"))
    print(sff.dpctl("add-flow", f"priority=100,icmp,in_port=3,nw_dst=11.0.0.2,actions=output:2"))


# redirecting traffic from vnf to original recipients

    # default is to drop packets
    print(vnf.cmd('iptables -P INPUT DROP'))
    print(vnf.cmd('iptables -P FORWARD DROP'))
    print(vnf.cmd('iptables -P OUTPUT DROP'))

    # loopback interface is permitted
    print(vnf.cmd('iptables -A INPUT -i lo -j ACCEPT'))
    print(vnf.cmd('iptables -A OUTPUT -o lo -j ACCEPT'))

    # accepting packets from switch
    print(vnf.cmd('iptables -A INPUT -i eth0 -s 11.0.0.0/24 -j ACCEPT'))

    print(vnf.cmd('iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT'))

    # redirecting traffic to switch
    print(vnf.cmd('iptables -A OUTPUT -s 11.0.0.0/24 -d 11.0.0.0/24 -o eth0 -j ACCEPT'))
# -------------------------------------------------------------------------- #

    print(sff.dpctl("show"))
    net.ping([dh1, dh2])
    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
