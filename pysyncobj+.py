import sys
import time
import json
from colorama import Fore
from functools import partial
from pysyncobj import SyncObj, replicated, SyncObjConf
import datetime
from cpu_monitor import CPUMonitor
from memory_monitor import MemoryMonitor
from pki_setup import PKI
import os
from request import get_ca_status, submit_csr_to_ca

if __name__ == '__main__':  
    if len(sys.argv) < 3:
        print('Usage: %s node_name key_size' % sys.argv[0])
        print('Available nodes: node1, node2, node3, node4')
        sys.exit(-1)

    node_name = sys.argv[1]

    status = get_ca_status()
    print(Fore.CYAN + f'CA Status: {status}')

    if not os.path.exists('pki_private_key.pem'):
        print(Fore.YELLOW + 'No private key found, generating...')
        pki = PKI()
        pki.generate_keys()
        pki.generate_csr()
        print(Fore.YELLOW + 'About to submit CSR to CA...')
        result = submit_csr_to_ca(node_name)
        print(Fore.YELLOW + f'CSR submission result: {result}')
        if os.path.exists('certificate.pem'):
            print(Fore.GREEN + 'Certificate file created successfully!')
        else:
            print(Fore.RED + 'Certificate file was NOT created!')

    if not os.path.exists(f'{node_name}_certificate.pem'):
        print(Fore.RED + f'Error: No Certificate Found for {node_name}! Cannot Start PySyncObj!!')
        exit(0)

    print(Fore.GREEN + f'Certificate Found Starting PySyncObj!')

    # Set NODE_NAME environment variable BEFORE creating Raft object
    os.environ['NODE_NAME'] = node_name

    class Raft(SyncObj):
        def __init__(self, selfNodeAddr, otherNodeAddrs, nodes_data, node_name):
            print("\n" + "="*70)
            print("🚀 USING UPDATED SCRIPT WITH COUNTER DISPLAY!")
            print("="*70 + "\n")
            
            conf = SyncObjConf()
            conf.logCompactionMinEntries = 2
            conf.logCompactionMinTime = 2
            conf.password = "SecureRaft2026"
            conf.encryptor = True
            conf.node_name = node_name  # ← Add this line for PySyncObj+
            super(Raft, self).__init__(selfNodeAddr, otherNodeAddrs, conf) 
            self.__counter = 0
            self.nodes_data = nodes_data

        @replicated
        def incCounter(self):
            self.__counter += 1
        
        @replicated
        def addValue(self, value, cn): 
            print(f"\n{'='*60}")
            print(f"📊 [{node_name}] COUNTER OPERATION:")
            print(f"   Value to add: {value}")
            print(f"   Counter before: {self.__counter}")
            print(f"   Counter after: {self.__counter + value}")
            print(f"{'='*60}\n")
            
            self.__counter += value
            return self.__counter, cn
        
        def getCounter(self):
            return self.__counter

        def getNodes(self):
            print(self.nodes_data)  
            return self.nodes_data

        def run_scripts(self):
            memory_monitor = MemoryMonitor()
            cpu_monitor = CPUMonitor()
            memory_monitor.start_monitoring()
            cpu_monitor.start_monitoring()

    def onAdd(res, err, cnt):
        print('onAdd %d:' % cnt, res, err)

    with open('nodes.json', 'r') as file:
        nodes = json.load(file)
    
    if node_name not in nodes:
        print(Fore.RED + f'Error: Node {node_name} not found in nodes.json')
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
    o = Raft(self_addr, partner_addrs, nodes, node_name)  # ← Pass node_name

    with open('rsa_keys.json', 'r') as file:
        rsa_keys = json.load(file)

    key_size = sys.argv[2]
    if key_size not in rsa_keys:
        print(Fore.RED + f'Error: Key {key_size} not Found in rsa_keys.json')
        sys.exit(-1)

    n = 0
    old_value = -1
    
    while True:
        time.sleep(0.5)
        
        # Always try to increment if we're the leader
        if o._getLeader() is not None and n < 20:
            print(f"\n🚀 [{node_name}] Attempting to add value, n={n}")
            o.addValue(10, n, callback=partial(onAdd, cnt=n))
            n += 1
        
        # Show counter value
        current = o.getCounter()
        if current != old_value:
            old_value = current
            print(f"📈 Counter changed to: {current}")
