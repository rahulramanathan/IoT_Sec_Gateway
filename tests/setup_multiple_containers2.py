import argparse
import shlex
import subprocess
import itertools
import ipaddress
import threading

NODE_0='192.1.1.2'
NODE_1='10.1.1.2'
BRIDGE='br0'
NUM_THREADS=32

# Syntax: python 

def attach_container(bridge, container_name):
    interfaces=('eth0', 'eth1')
    for interface in interfaces:
        cmd = '/usr/bin/sudo /usr/bin/ovs-docker add-port {} {} {}'
        cmd = cmd.format(bridge, interface, container_name)
        subprocess.check_call(shlex.split(cmd))

def find_container_ports(bridge, container_name):
    interfaces=('eth0', 'eth1')
    of_ports = []
    for interface in interfaces:
        cmd='/usr/bin/sudo /usr/bin/ovs-vsctl --data=bare --no-heading \
             --columns=name find interface external_ids:container_id={} \
             external_ids:container_iface={}'
        cmd = cmd.format(container_name, interface)
        ovs_port = subprocess.check_output(cmd, shell=True)
        ovs_port = ovs_port.strip()
        cmd='/usr/bin/sudo /usr/bin/ovs-ofctl show {} | grep {}'
        cmd=cmd.format(bridge, ovs_port) + " | awk -F '(' '{ print $1 }'"
        of_port = subprocess.check_output(cmd, shell=True)
        of_port= of_port.strip()
        of_ports.append(of_port)
    return of_ports

def pairwise(iterable):
    's -> (s0, s1), (s2, s3), s4, s5), ...'
    a = iter(iterable)
    return itertools.izip(a,a)

def connect_container(bridge, client_ip, server_ip, container_name):
    interfaces=('eth0', 'eth1')
    of_ports = find_container_ports(bridge, container_name)
    of_ports = [1] + of_ports + [2]
    # Connect client to server (direction = 1 (only client to server) or 3)
    for in_port,out_port in pairwise(of_ports):
        cmd='/usr/bin/sudo /usr/bin/ovs-ofctl add-flow {} "priority=100 ip in_port={} nw_src={} nw_dst={} actions=output:{}"'
        cmd=cmd.format(bridge, in_port, client_ip, server_ip, out_port)
        subprocess.check_call(shlex.split(cmd))
    # Connect server to client (direction=2 (only server to client) or 3)
    for in_port,out_port in pairwise(reversed(of_ports)):
        cmd='/usr/bin/sudo /usr/bin/ovs-ofctl add-flow {} "priority=100 ip in_port={} nw_src={} nw_dst={} actions=output:{}"'
        cmd=cmd.format(bridge, in_port, server_ip, client_ip, out_port)
        subprocess.check_call(shlex.split(cmd))

def get_names(number):
    list=['test{}'.format(i) for i in range(number)]
    return list

def get_ip_range(base_ip, num):
    try:
        base_ip = ipaddress.ip_address(unicode(base_ip))
    except:
        print('Invalid ip address: {}'.format(base_ip))
        sys.exit(1)
    ips = [base_ip + i for i in range(num)]
    return ips

def start_containers(self, container, name):
    cmd='/usr/bin/sudo /usr/bin/docker run -itd --rm --network=none --privileged --name {} {}'
    cmd=cmd.format(name, container)
    subprocess.check_call(shlex.split(cmd))


class setup_threads(object):
    queue=[]
    thread_count=NUM_THREADS
    lock=threading.Lock()
    container=[]
    client_ips=[]
    server_ips=[]
    name_list=[]

    def setup_container(self, i):
        start_containers(self.container, self.name_list[i])
        attach_container(BRIDGE, self.name_list[i])
        connect_container(BRIDGE, self.client_ips[0], self.server_ips[i], self.name_list[i])
        
    def pop_queue(self):
        cmd_str=None
        self.lock.acquire()
        if self.queue:
            cmd_str=self.queue.pop()
        self.lock.release()
        return cmd_str

    def dequeue(self):
        while True:
            cmd_str=self.pop_queue()
            if not cmd_str:
                return None
            self.setup_container(cmd_str)

    def start(self):
        threads=[]
        for i in range(self.thread_count):
            t=threading.Thread(target=self.dequeue)
            t.start()
            threads.append(t)
        [ t.join() for t in threads ]
        

def main():
    parser=argparse.ArgumentParser(description='Connect container to vswitch')
    parser.add_argument('--container', '-C', required=True, type=str)
#    parser.add_argument('--name', '-N', required=True, type=str)
    parser.add_argument('--instances', '-n', required=True, type=int)
    args=parser.parse_args()
    name_list = []
    client_ips = []
    server_ips = []
    name_list = get_names(args.instances)
    client_ips = get_ip_range(NODE_0, args.instances)
    server_ips = get_ip_range(NODE_1, args.instances)
    queue=[]
    for i in range(0, len(name_list)):
        queue.append(i)
    setup_gen=setup_threads()
    setup_gen.thread_count=NUM_THREADS
    setup_gen.queue=queue
    setup_gen.name_list=name_list
    setup_gen.client_ips=client_ips
    setup_gen.server_ips=server_ips
    setup_gen.start()

if __name__ == '__main__':
    main()
    

