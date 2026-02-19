import sys
import time
import json
from colorama import Fore, Style
from functools import partial
from pysyncobj import SyncObj, replicated, SyncObjConf
import datetime
from cpu_monitor import CPUMonitor
from memory_monitor import MemoryMonitor
from pki_setup import PKI
import os
from request import get_ca_status, submit_csr_to_ca

memory_monitor = MemoryMonitor()
cpu_monitor = CPUMonitor()

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

    print(Fore.GREEN + f'Certificate Found — Starting PySyncObj!')
    os.environ['NODE_NAME'] = node_name

    def _set_enc_ctx(label: str):
        """Tag the encryptor so its one-liner shows the Raft operation name."""
        try:
            from encryptor import RSAEncryptor
            RSAEncryptor.set_context(label)
        except Exception:
            pass

    class Raft(SyncObj):
        def __init__(self, selfNodeAddr, otherNodeAddrs, nodes_data, node_name):
            print("\n" + "="*60)
            print(f" RAFT NODE  [{node_name}]  starting up")
            print("="*60 + "\n")

            conf = SyncObjConf()
            conf.logCompactionMinEntries = 2
            conf.logCompactionMinTime = 2
            conf.password = "SecureRaft2026"
            conf.encryptor = True
            conf.node_name = node_name
            super(Raft, self).__init__(selfNodeAddr, otherNodeAddrs, conf)
            self.__counter = 0
            self.nodes_data = nodes_data
            self._last_leader = None

        @replicated
        def incCounter(self):
            _set_enc_ctx("incCounter → replicate")
            self.__counter += 1

        @replicated
        def addValue(self, value, cn):
            _set_enc_ctx(f"addValue({value}) → replicate")
            self.__counter += value

            print(
                f"\n  {'─'*54}\n"
                f"RAFT LOG ENTRY  [{node_name}]  seq={cn}\n"
                f"addValue({value})  |  counter: {self.__counter - value} → "
                f"{Fore.GREEN}{self.__counter}{Style.RESET_ALL}\n"
                f"  {'─'*54}"
            )
            return self.__counter, cn

        def getCounter(self):
            return self.__counter

        def getNodes(self):
            print(self.nodes_data)
            return self.nodes_data

        def _getLeader(self):
            leader = super()._getLeader()
            
            if leader != self._last_leader:
                if leader:
                    try:
                        self_addr = self._selfAddress
                    except AttributeError:
                        self_addr = None
                    is_me = (self_addr is not None and leader == self_addr)
                    role_label = "THIS NODE" if is_me else f"peer  (I am {self_addr or '?'})"
                    print(
                        f"\n  {'='*54}\n"
                        f"RAFT LEADER  →  {leader}  [{role_label}]\n"
                        f"  {'='*54}\n"
                    )
                self._last_leader = leader
            return leader

    def onAdd(res, err, cnt):
        status = Fore.GREEN + "OK" + Style.RESET_ALL if err is None else Fore.RED + str(err) + Style.RESET_ALL
        print(f"  ✔  onAdd seq={cnt}  result={res}  {status}")

    with open('nodes.json', 'r') as file:
        nodes = json.load(file)

    if node_name not in nodes:
        print(Fore.RED + f'Error: Node {node_name} not found in nodes.json')
        sys.exit(-1)

    self_node = nodes[node_name]
    self_addr = f"{self_node['addr']}:{self_node['port']}"

    partner_addrs = [
        f"{info['addr']}:{info['port']}"
        for name, info in nodes.items() if name != node_name
    ]

    print(f"  self  : {self_addr}")
    print(f"  peers : {partner_addrs}\n")

    o = Raft(self_addr, partner_addrs, nodes, node_name)
    memory_monitor.start_monitoring()
    cpu_monitor.start_monitoring()

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

        leader = o._getLeader()

        if leader is not None and n < 20:
            _set_enc_ctx(f"addValue(10) seq={n} → send")
            print(f"  ->  [{node_name}] addValue(10)  seq={n}")
            o.addValue(10, n, callback=partial(onAdd, cnt=n))
            n += 1

        current = o.getCounter()
        if current != old_value:
            old_value = current
            print(f"[{node_name}] counter = {Fore.CYAN}{current}{Style.RESET_ALL}")
