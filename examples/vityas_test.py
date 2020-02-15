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


def virtual_network_function():
    return None


def topology():
    "Create a network with some docker containers acting as hosts."

    net = Containernet(controller=Controller)

    info('*** Adding controller\n')
    net.addController('c0')

    info('*** Adding docker containers (as hosts)\n')
    dh1, dh2 = [net.addHost(f"dh{i}", ip=f'11.0.0.{i}', cls=Docker,
                            dimage='ubuntu:trusty', cpu_shares=20) for i in range(1, 3)]

    info('*** Adding SFF\n')
    sff = net.addServiceFunctionForwarder('s1', cls=OVSSwitch)

    info('*** Adding VNF\n')
    vnf = net.addVirtualNetworkFunction('v1')

    info('*** Creating links\n')
    for i in [dh1, dh2]:
        net.addLink(i, sff)

    info('*** Starting network\n')
    net.start()

    net.ping([dh1, dh2])

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
