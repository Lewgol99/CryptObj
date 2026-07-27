import sys
import time 
import json
import threading
from colorama import Fore, Style
from functools import partial
from pysyncobj import SyncObj, replicated, SyncObjConf
import datetime
from pki_setup import PKI
import os
from request import get_ca_status, submit_csr_to_ca, fetch_all_certificates
from encryptor import AsymmetricEncryptor
from digital_signature import DigitalSignature
from latency_monitor import LatencyMonitor  # unmodified — only imported, not edited

if __name__ == '__main__':

    NO_CRYPTO = '--no-crypto' in sys.argv
    if NO_CRYPTO:
        sys.argv.remove('--no-crypto')
    # ─────────────────────────────────────────────────────────────────────

    with open('scale_nodes.json', 'r') as file:
        nodes = json.load(file)

    with open('asymmetric_ciphers.json', 'r') as file:
        config = json.load(file)

    with open('rsa_keys.json', 'r') as file:
        rsa_keys = json.load(file)

    with open('ecc_curves.json', 'r') as file:
        curves = json.load(file)

    with open('ciphers.json', 'r') as file:
        ciphers = json.load(file)

    if len(sys.argv) < 5:
        print(Fore.YELLOW + f'Usage: {sys.argv[0]} node_name, asymmetric_cipher, key_size/curve, symmetric_cipher')
        print(Fore.YELLOW + f'Available nodes: {list(nodes.keys())}')
        print(Fore.YELLOW + f'Available asymmetric ciphers: {config["asymmetric_ciphers"]}')
        print(Fore.YELLOW + f'Available key sizes: {rsa_keys["key_sizes"]}')
        print(Fore.YELLOW + f'Available ciphers: {ciphers["ciphers"]}')
        sys.exit(-1)

    node_name = sys.argv[1]

    status = get_ca_status()
    print(Fore.YELLOW + f'CA Status: {status}')

    print(Fore.YELLOW + f'Certificate Found — Starting PySyncObj!')
    os.environ['NODE_NAME'] = node_name

    def _set_enc_ctx(label: str):
        try:
            from encryptor import AsymmetricEncryptor
            AsymmetricEncryptor.set_context(label)
        except Exception:
            pass

    class Raft(SyncObj):
        def __init__(self, selfNodeAddr, otherNodeAddrs, nodes_data, node_name):
            print("\n" + "="*60)
            print(f" RAFT NODE  [{node_name}]  starting up")
            print("="*60 + "\n")

            conf = SyncObjConf()
            # CHANGED: these were logCompactionMinEntries=2 / logCompactionMinTime=2,
            # which triggers log compaction after just 2 entries or 2 seconds.
            # That's aggressive enough to truncate a follower's log journal
            # to empty while it's still catching up, which pysyncobj's
            # MemoryJournal.__getitem__ doesn't guard against - it then
            # throws IndexError: list index out of range on every internal
            # tick from then on (self.__raftLog[0][1] / [-1][1] on an empty
            # list), permanently wedging that node for the rest of the run.
            # Using PySyncObj's own defaults (logCompactionMinEntries=5000)
            # and raising logCompactionMinTime well above the total expected
            # run length (baseline + load phases) so compaction can't fire
            # mid-run at all - same fix already applied in pysyncobj+.py.
            conf.logCompactionMinTime = 7200
            conf.password = None if NO_CRYPTO else "SecureRaft2026"  # <- --no-crypto toggle
            conf.node_name = node_name
            conf.connectionTimeout = 30.0
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

    # seq -> perf_counter() at send time; keyed because addValue is fire-and-forget
    # and more than one commit can be in flight when replication is slow.
    pending_latency = {}

    def onAdd(res, err, cnt):
        status = Fore.GREEN + "OK" + Style.RESET_ALL if err is None else Fore.RED + str(err) + Style.RESET_ALL
        print(f"onAdd seq={cnt}  result={res}  {status}")

        start = pending_latency.pop(cnt, None)
        if start is not None:
            latency_ms = (time.perf_counter() - start) * 1000
            label = f'raft_roundtrip_load_seq{cnt}' + ('_no_crypto' if NO_CRYPTO else '')
            load_monitor._results_list.append({
                'measurement': len(load_monitor._results_list) + 1,
                'label': label,
                'latency_ms': round(latency_ms, 6)
            })
            print(f"  roundtrip [{label}]: {latency_ms:.3f} ms")
            load_monitor.append_last('commit_measurements_load')

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

    asymmetric_cipher = sys.argv[2]
    if asymmetric_cipher not in config['asymmetric_ciphers']:
        print(Fore.RED + f'Error: {asymmetric_cipher} not found in asymmetric_ciphers.json')
        sys.exit(-1)

    key_param = sys.argv[3]

    if '--tls' in sys.argv:
        tls_index = sys.argv.index('--tls')
        tls_group = sys.argv[tls_index + 1]
        if tls_group not in curves['ec_curves']:
            print(Fore.RED + f'Error: {tls_group} not found in ec_curves.json')
            sys.exit(-1)
        del sys.argv[tls_index:tls_index + 2]
        os.environ['USE_TLS'] = tls_group

        if not os.path.exists('certificate.pem'):
            from request import fetch_root_certificate
            print(Fore.CYAN + 'Fetching CA root certificate for TLS...')
            fetch_root_certificate()

    if asymmetric_cipher == 'RSA':
        key_size = int(key_param)
        if key_size not in rsa_keys['key_sizes']:
            print(Fore.RED + f'Error: Key {key_size} not Found in rsa_keys.json')
            sys.exit(-1)
    elif asymmetric_cipher == 'ECC':
        curve_name = key_param
        if curve_name not in curves['ec_curves']:
            print(Fore.RED + f'Error: Curve {curve_name} not Found in ec_curves.json')
            sys.exit(-1)

    selected_ciphers = sys.argv[4]
    if selected_ciphers not in ciphers['ciphers']:
        print(Fore.RED + f'Error: Cipher {selected_ciphers} not Found in ciphers.json')
        sys.exit(-1)
    os.environ['SELECTED_CIPHER'] = selected_ciphers
    AsymmetricEncryptor.set_cipher(selected_ciphers)

    if not os.path.exists('pki_private_key.pem'):
        print(Fore.YELLOW + 'No private key found, generating...')
        if asymmetric_cipher == 'RSA':
            pki = PKI()
            pki.generate_keys(key_size)
            pki.generate_csr(node_name)
            result = submit_csr_to_ca(node_name)
        elif asymmetric_cipher == 'ECC':
            pki = PKI()
            pki.generate_ecc_keys(curve_name)
            pki.generate_csr(node_name)
            result = submit_csr_to_ca(node_name)
        print(Fore.CYAN + 'Fetching all certificates in parallel...')
        fetch_all_certificates(node_name)
        print(Fore.GREEN + 'All certificates fetched — starting Raft!')

    if not os.path.exists('signing_private_key.pem'):
        print(Fore.YELLOW + 'No signing key found, generating...')
        signer = DigitalSignature()
        if asymmetric_cipher == 'RSA':
            signer.generate_Private_Key(key_size)
        elif asymmetric_cipher == 'ECC':
            signer.generate_Private_Key(curve_name)
        signer.serialize_Private_key()
        signer.serialize_Public_key()
        print(Fore.GREEN + 'Signing keys generated!')

    if not os.path.exists(f'{node_name}_certificate.pem'):
        print(Fore.RED + f'Error: No Certificate Found for {node_name}! Cannot Start PySyncObj!!')
        exit(0)

    o = Raft(self_addr, partner_addrs, nodes, node_name)

    # Dedicated monitors: baseline (Phase 1, closed-loop) is kept fully
    # separate from load (Phase 2, open-loop) so the two measurement
    # regimes can never end up averaged into one number.
    latency_monitor = LatencyMonitor()   # Phase 1: baseline commit latency
    load_monitor = LatencyMonitor()      # Phase 2: latency under concurrent load

    # ── Wait for Raft to stabilise before sending ──────────────────────────
    print(Fore.YELLOW + f'[{node_name}] Waiting for leader election...')
    while o._getLeader() is None:
        time.sleep(1)
    print(Fore.GREEN + f'[{node_name}] Leader found — waiting 10s for network to stabilise...')
    time.sleep(10)
    # ───────────────────────────────────────────────────────────────────────

    # ── PHASE 1: closed-loop baseline commit latency ────────────────────────
    # One commit at a time, blocking until it's actually committed before
    # sending the next — no overlap, so nothing here can queue/contend.
    # This is the number that belongs in the paper as "Raft commit latency".
    print(Fore.GREEN + f'[{node_name}] Starting baseline (closed-loop) measurement...')
    N_BASELINE_SAMPLES = 250

    def measure_commit_blocking(seq):
        done = threading.Event()
        outcome = {}

        def callback(res, err):
            outcome['t'] = time.perf_counter()
            outcome['err'] = err
            done.set()

        start = time.perf_counter()
        _set_enc_ctx(f"addValue(10) seq={seq} → send")
        o.addValue(10, seq, callback=callback)

        if not done.wait(timeout=10):
            print(Fore.RED + f'  seq={seq} timed out — recording as censored sample')
            label = f'raft_roundtrip_seq{seq}_TIMEOUT' + ('_no_crypto' if NO_CRYPTO else '')
            latency_monitor._results_list.append({
                'measurement': len(latency_monitor._results_list) + 1,
                'label': label,
                'latency_ms': ''
            })
            return

        if outcome['err'] is not None:
            print(Fore.RED + f'  seq={seq} failed: {outcome["err"]}')
            return

        latency_ms = (outcome['t'] - start) * 1000
        label = f'raft_roundtrip_seq{seq}' + ('_no_crypto' if NO_CRYPTO else '')
        latency_monitor._results_list.append({
            'measurement': len(latency_monitor._results_list) + 1,
            'label': label,
            'latency_ms': round(latency_ms, 6)
        })
        print(f"  roundtrip [{label}]: {latency_ms:.3f} ms")
        latency_monitor.append_last('commit_measurements')

    for seq in range(N_BASELINE_SAMPLES):
        while o._getLeader() is None:
            time.sleep(0.5)
        measure_commit_blocking(seq)

    latency_monitor.save_file('commit_measurements')
    print(Fore.GREEN + f'[{node_name}] Saved {len(latency_monitor._results_list)} '
          f'baseline measurements to commit_measurements.csv')

    # ── PHASE 2: open-loop latency under concurrent load ────────────────────
    # Unchanged from before: fires every 0.5s regardless of whether prior
    # commits have finished, so latency here reflects queueing/contention
    # under load, not isolated commit latency. Kept as a separate dataset.
    print(Fore.GREEN + f'[{node_name}] Starting load (open-loop) measurement...')

    n = 0
    old_value = -1
    RUN_DURATION = 600   # run for 10 minutes — adjust as needed
    start_time = time.time()

    while True:
        time.sleep(0.5)

        # Stop after RUN_DURATION seconds
        if time.time() - start_time > RUN_DURATION:
            print(Fore.CYAN + f'[{node_name}] Run duration reached ({RUN_DURATION}s). Stopping.')
            break

        leader = o._getLeader()

        if leader is not None:
            _set_enc_ctx(f"addValue(10) seq={n} → send")
            print(f"  ->  [{node_name}] addValue(10)  seq={n}")
            pending_latency[n] = time.perf_counter()
            o.addValue(10, n, callback=partial(onAdd, cnt=n))
            n += 1

        current = o.getCounter()
        if current != old_value:
            old_value = current
            print(f"[{node_name}] counter = {Fore.CYAN}{current}{Style.RESET_ALL}")

    load_monitor.save_file('commit_measurements_load')
    print(Fore.GREEN + f'[{node_name}] Saved {len(load_monitor._results_list)} '
          f'load measurements to commit_measurements_load.csv')
