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
    actual documentation stores at https://www.lucidchart.com/documents/edit/e71c5614-f991-4091-97ca-f18bdd5c5219/0_0?beaconFlowId=A019EEC6C933FCF3
"""

from mininet.net import Containernet
from mininet.node import Controller, Docker, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from datetime import datetime
import time
import csv


from mininet.link import TCLink, Link


def rules_for_first_vnf(sff: OVSSwitch, vnf_f, vnf_l):
    print(sff.dpctl("add-flow", f"icmp,in_port=1,actions=output:3"))
    print(sff.dpctl("add-flow", f"icmp,in_port=2,actions=output:4"))
    print(sff.dpctl("add-flow", f"udp,in_port=1,actions=output:3"))
    print(sff.dpctl("add-flow", f"udp,in_port=2,actions=output:4"))


def rules_from_vnf_to_hosts(sff: OVSSwitch, dh1, dh2):
    for i in (3, 4):
        print(sff.dpctl("add-flow", f"icmp,in_port={i},nw_dst={dh1.IP()},actions=output:1"))
        print(sff.dpctl("add-flow", f"icmp,in_port={i},nw_dst={dh2.IP()},actions=output:2"))
        print(sff.dpctl("add-flow", f"udp,in_port={i},nw_dst={dh1.IP()},actions=output:1"))
        print(sff.dpctl("add-flow", f"udp,in_port={i},nw_dst={dh2.IP()},actions=output:2"))
        # print(sff.dpctl("add-flow", f"table=1,nsh_mdtype=1,actions=decap(packet_type(ns=0,type=0x894f))"))
        # print(sff.dpctl("add-flow", f"icmp,in_port={i},nw_dst={dh1.IP()},actions=mod_dl_dst:{dh1.MAC()},output:1"))
        # print(sff.dpctl("add-flow", f"icmp,in_port={i},nw_dst={dh2.IP()},actions=mod_dl_dst:{dh2.MAC()},output:2"))
        # print(sff.dpctl("add-flow", f"udp,in_port={i},nw_dst={dh1.IP()},actions=mod_dl_dst:{dh1.MAC()},output:1"))
        # print(sff.dpctl("add-flow", f"udp,in_port={i},nw_dst={dh2.IP()},actions=mod_dl_dst:{dh2.MAC()},output:2"))
        # print(sff.dpctl("add-flow", f"table=1,nsh_mdtype=1,actions=decap(packet_type(ns=0,type=0x894f))"))


def rules_for_chaining(list_of_vnfs, list_of_sffs):
    # print(vnf.cmd(f'iptables -A OUTPUT -s 11.0.0.0/24 -d 11.0.0.0/24 -o eth0 -j ACCEPT'))
    for v in list_of_vnfs:
        # setting brctl on vnf
        print(v.cmd(f'brctl addbr test'))
        print(v.cmd(f'brctl addif test {v.name}-eth0 {v.name}-eth1'))
        print(v.cmd(f'echo 1 > /proc/sys/net/ipv4/ip_forward'))
        print(v.cmd(f'sysctl -w net.bridge.bridge-nf-call-iptables=0'))
        print(v.cmd(f'sysctl -w net.bridge.bridge-nf-call-ip6tables=0'))
        print(v.cmd(f'sysctl -w net.bridge.bridge-nf-call-arptables=0'))
        print(v.cmd(f'ifconfig test up'))  # activating bridge
        print(v.cmd(f'ifconfig eth0 down'))  # activating bridge
        # print(v.cmd(f'iptables -A FORWARD -s 11.0.0.1 -d 11.0.0.2 -i {v.name}-eth0 -o {v.name}-eth1 -j ACCEPT'))
        # print(v.cmd(f'iptables -A FORWARD -s 11.0.0.2 -d 11.0.0.1 -i {v.name}-eth0 -o {v.name}-eth0 -j ACCEPT'))
        print(v.cmd(f'iptables -A FORWARD -o test -j ACCEPT'))


def rules_for_mac_chaining(list_of_sffs, list_of_vnfs, dh1, dh2):
    i = 1
    for s in list_of_sffs:
        print(s.dpctl("add-flow", f"icmp,in_port=1,actions=output:2"))
        print(s.dpctl("add-flow", f"icmp,in_port=2,actions=output:1"))
        print(s.dpctl("add-flow", f"udp,in_port=1,actions=output:2"))
        print(s.dpctl("add-flow", f"udp,in_port=2,actions=output:2"))


        '''
            правила ниже работают для мак чейнинга при этом контейнернет глючит и не даёт выполниться правилам с resubmit - при том что из текстового файла напрямую в xterm свитчи настраиваются нормально
        '''
        # print(s.dpctl("add-flow", f"table=0,icmp,in_port=1,actions=mod_dl_dst:{list_of_vnfs[i].MAC()},resubmit:(,1)"))
        # print(s.dpctl("add-flow", f"table=0,icmp,in_port=2,actions=mod_dl_dst:{list_of_vnfs[i - 1].MAC()},resubmit:(,1)"))
        # print(s.dpctl("add-flow", f"table=0,udp,in_port=1,actions=mod_dl_dst:{list_of_vnfs[i].MAC()},resubmit:(,1)"))
        # print(s.dpctl("add-flow", f"table=0,udp,in_port=2,actions=mod_dl_dst:{list_of_vnfs[i - 1].MAC()},resubmit:(,1)"))
        #
        # print(s.dpctl("add-flow", f"table=1,icmp,dl_dst={list_of_vnfs[i].MAC()},actions=mod_dl_dst:{dh2.MAC()},output:2"))
        # print(s.dpctl("add-flow", f"table=1,icmp,dl_dst:{list_of_vnfs[i - 1].MAC()},actions=mod_dl_dst:{dh1.MAC()},output:1"))
        # print(s.dpctl("add-flow", f"table=1,udp,dl_dst:{list_of_vnfs[i].MAC()},actions=mod_dl_dst:{dh2.MAC()},output:2"))
        # print(s.dpctl("add-flow", f"table=1,udp,dl_dst:{list_of_vnfs[i - 1].MAC()},actions=mod_dl_dst:{dh1.MAC()},output:1"))
        i += 1



def create_simple_chain(list_of_vnfs, sff: OVSSwitch, net: Containernet, list_of_sffs, delay):
    first, last = list_of_vnfs[0], list_of_vnfs[-1]
    net.addLink(first, sff, cls=TCLink, delay=delay)

    # other_vnfs = list_of_vnfs[1:-1]
    for i in range(len(list_of_vnfs) - 1):
        net.addLink(list_of_vnfs[i], list_of_sffs[i])
        net.addLink(list_of_sffs[i], list_of_vnfs[i + 1])

    net.addLink(last, sff, cls=TCLink, delay=delay)
    rules_for_chaining(list_of_vnfs, list_of_sffs)


def topology():
    """Create a network with some docker containers acting as hosts.
    """
    delay_list = ['5ms', '10ms', '20ms', '40ms', '60ms', '100ms']
    with open('test_increasing_delay.csv', 'w') as csvfile:
        fieldnames = ['delay', 'startup', 'vnf_deployment', 'deletion', 'ping']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for delay in delay_list:
            start_time = datetime.now()

            net = Containernet(controller=Controller)

            # info('*** Adding controller\n')
            # net.addController('c0')

            info('*** Adding docker containers (as hosts)\n')
            # dh3 = [net.addHost(f"dh{3}", ip=f'11.0.0.{4}', cls=Docker,
            #                         dimage='devrt/container-firewall:latest', cpu_shares=20)]
            dh1, dh2 = [net.addHost(f"dh{i}", ip=f'11.0.0.{i}', cls=Docker,
                                    dimage='vityaszv/custom_container:latest', cpu_shares=20) for i in range(1, 3)]
            amount_of_hosts = 2
            info('*** Adding SFF\n')
            sff = net.addServiceFunctionForwarder('s1', cls=OVSSwitch)

            info('*** Creating links\n')

            for el in [dh1, dh2]:
                net.addLink(el, sff, cls=TCLink, delay=delay)

            info('*** Adding VNFs\n')


            vnf_deploy_start = datetime.now()
            vnf1, vnf2, vnf3 = [
                net.addVirtualNetworkFunction(f'v{i - 2}', dimage="vityaszv/custom_container:latest", switch=sff,
                                              ip=f'11.0.0.{i}')
                for i in range(3, 6)]
            v_amount = 3
            vnf_deploy_finish = datetime.now()


            list_of_sffs = [net.addServiceFunctionForwarder(f's{i}', cls=OVSSwitch) for i in range(2, v_amount + 1)]
            print(f'size of sffs: {len(list_of_sffs)}')

            create_simple_chain([vnf1, vnf2, vnf3], sff, net, list_of_sffs, delay)
            info('*** Starting network\n')
            net.start()

            print(sff.dpctl("add-flow", "arp,actions=normal"))

            # adding flows for redirecting traffic from dh1 dh2 to v1 - with changing mac_dst
            rules_for_first_vnf(sff, vnf1, vnf3)

            # rules from packets from vmf to hosts
            rules_from_vnf_to_hosts(sff, dh1, dh2)

            # rules for mac chaining
            rules_for_mac_chaining(list_of_sffs, [vnf1, vnf2, vnf3], dh1, dh2)

            """
                thats iptables rules, possibly unneeded
            """
            # # adding rules to dh1 and dh2
            # # -- forward rule
            # print(dh1.cmd('iptables -A FORWARD -s 11.0.0.1 -d 11.0.0.2 -o eth0 -j ACCEPT'))
            # print(dh2.cmd('iptables -A FORWARD -s 11.0.0.2 -d 11.0.0.1 -o eth0 -j ACCEPT'))
            # # -- output rules
            # print(dh1.cmd('iptables -A OUTPUT -s 11.0.0.1 -d 11.0.0.2 -o eth0 -j ACCEPT'))
            # print(dh2.cmd('iptables -A OUTPUT -s 11.0.0.2 -d 11.0.0.1 -o eth0 -j ACCEPT'))

            """
                   thats iptables rules, possibly unneeded
            """
            # # redirecting traffic from vnf to original recipients
            #
            #     # default is to drop packets
            #     print(vnf.cmd('iptables -P INPUT DROP'))
            #     print(vnf.cmd('iptables -P FORWARD DROP'))
            #     print(vnf.cmd('iptables -P OUTPUT DROP'))
            #
            #     # loopback interface is permitted
            #     print(vnf.cmd('iptables -A INPUT -i lo -j ACCEPT'))
            #     print(vnf.cmd('iptables -A OUTPUT -o lo -j ACCEPT'))
            #
            #     # accepting packets from switch
            #     print(vnf.cmd('iptables -A INPUT -i eth0 -s 11.0.0.0/24 -j ACCEPT'))
            #
            #     print(vnf.cmd('iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT'))
            #
            #     # redirecting traffic to switch
            #     print(vnf.cmd('iptables -A OUTPUT -s 11.0.0.0/24 -d 11.0.0.0/24 -o eth0 -j ACCEPT'))
            # -------------------------------------------------------------------------- #

            print(sff.dpctl("show"))
            # info('*** Running CLI\n')
            # CLI(net)
            start_time_finish = datetime.now()

            ping_start = datetime.now()
            net.ping([dh1, dh2])
            net.ping([dh2, dh1])
            ping_stop = datetime.now()

            info('*** Stopping network')
            stop_time_start = datetime.now()
            net.stop()
            stop_time_finish = datetime.now()
            writer.writerow({
                'delay': delay,
                'startup': start_time_finish - start_time,
                'vnf_deployment': vnf_deploy_finish - vnf_deploy_start,
                'deletion': stop_time_finish - stop_time_start,
                'ping': ping_stop - ping_start
            })
            csvfile.flush()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
