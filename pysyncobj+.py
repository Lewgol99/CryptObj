import sys
import time
import json
from functools import partial
from pysyncobj import SyncObj, replicated, SyncObjConf
import datetime
from cpu_monitor import CPUMonitor
from memory_monitor import MemoryMonitor
from asymmetric_keys import Asymmetric_Keys
from csr import CertificateSigningRequest

class Raft(SyncObj):
    def __init__(self, selfNodeAddr, otherNodeAddrs, nodes_data):
        conf = SyncObjConf()
        conf.logCompactionMinEntries = 2  # Completely disable log compaction
        conf.logCompactionMinTime = 2
        super(Raft, self).__init__(selfNodeAddr, otherNodeAddrs, conf) 
        self.__counter = 0
        self.nodes_data = nodes_data  # Store the nodes data

    @replicated
    def incCounter(self):
        self.__counter += 1
    
    @replicated
    def addValue(self, value, cn): 
        self.__counter += value
        return self.__counter, cn
    
    def getCounter(self):
        return self.__counter

    def getNodes(self):
        print(self.nodes_data)  
        return self.nodes_data

    def run_policies(self):
        # Create fresh instances each time - no serialization issues
        memory_monitor = MemoryMonitor()
        cpu_monitor = CPUMonitor()
        
        # Start monitoring
        memory_monitor.start_monitoring()
        cpu_monitor.start_monitoring()

        # start PKI
        asymkeygen = Asymmetric_Keys()
        csr = CertificateSigningRequest(private_key)

def onAdd(res, err, cnt):
    print('onAdd %d:' % cnt, res, err)

if __name__ == '__main__':  
    if len(sys.argv) < 2:
        print('Usage: %s node_name' % sys.argv[0])
        print('Available nodes: node1, node2, node3, node4')
        sys.exit(-1)

    with open('nodes.json', 'r') as file:
        nodes = json.load(file)
    
    node_name = sys.argv[1]
    
    if node_name not in nodes:
        print(f'Node {node_name} not found in nodes.json')
        sys.exit(-1)
    
    # Get this node's address
    self_node = nodes[node_name]
    self_addr = f"{self_node['addr']}:{self_node['port']}"
    
    # Get all partner addresses
    partner_addrs = []
    for name, node_info in nodes.items():
        if name != node_name:
            partner_addr = f"{node_info['addr']}:{node_info['port']}"
            partner_addrs.append(partner_addr)
    
    print(f"Starting {node_name} on {self_addr}, connecting to {partner_addrs}")
    o = Raft(self_addr, partner_addrs, nodes)  # Pass nodes data to constructor
    
    n = 0
    old_value = -1
    while True:
        time.sleep(0.5)
        if o.getCounter() != old_value:
            old_value = o.getCounter()
            print(old_value)
        if o._getLeader() is None:
            continue
        if n < 20:
            o.addValue(10, n, callback=partial(onAdd, cnt=n))
        
        if n % 10 == 0:
            o.run_policies()
            
        n += 1
