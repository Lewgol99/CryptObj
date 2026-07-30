import sys
import signal
import time 
import json
import threading
from colorama import Fore, Style
from functools import partial
from pysyncobj import SyncObj, replicated, SyncObjConf
from pysyncobj.syncobj import FAIL_REASON, _RAFT_STATE
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

    BOOTSTRAP_ITERATIONS = None
    if '--bootstrap' in sys.argv:
        bootstrap_index = sys.argv.index('--bootstrap')
        BOOTSTRAP_ITERATIONS = int(sys.argv[bootstrap_index + 1])
        del sys.argv[bootstrap_index:bootstrap_index + 2]
    BOOTSTRAP_COOLDOWN = 5.0  # seconds all nodes wait between rounds

    RUN_DURATION_SECONDS = None
    if '--duration' in sys.argv:
        duration_index = sys.argv.index('--duration')
        RUN_DURATION_SECONDS = float(sys.argv[duration_index + 1])
        del sys.argv[duration_index:duration_index + 2]
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

    election_monitor = LatencyMonitor()
    _election_start = [None]
    _first_election_seen = [False]  # first candidate→leader transition pays cold-start
                                     # connection/handshake cost (esp. under TLS) and is
                                     # discarded so recorded elections reflect steady-state
                                     # re-election latency, not cluster bootstrap.

    def onStateChanged(o, n):
        if n == _RAFT_STATE.CANDIDATE:
            _election_start[0] = time.perf_counter()
        elif n == _RAFT_STATE.LEADER and _election_start[0]:
            latency_ms = (time.perf_counter() - _election_start[0]) * 1000
            label = f'leader_election_{node_name}' + ('_no_crypto' if NO_CRYPTO else '')

            if not _first_election_seen[0]:
                _first_election_seen[0] = True
                print(Fore.YELLOW + f"  [cold-start election discarded]: {latency_ms:.3f} ms")
            else:
                election_monitor._results_list.append({
                    'measurement': len(election_monitor._results_list) + 1,
                    'label': label,
                    'latency_ms': round(latency_ms, 6)
                })
                print(Fore.CYAN + f"  election [{label}]: {latency_ms:.3f} ms")
                election_monitor.append_last('election_measurements')

            _election_start[0] = None
        elif n == _RAFT_STATE.FOLLOWER:
            _election_start[0] = None

    class Raft(SyncObj):
        def __init__(self, selfNodeAddr, otherNodeAddrs, nodes_data, node_name):
            print("\n" + "="*60)
            print(f" RAFT NODE  [{node_name}]  starting up")
            print("="*60 + "\n")

            conf = SyncObjConf()
            conf.password = None if NO_CRYPTO else "SecureRaft2026"  # <- --no-crypto toggle
            conf.node_name = node_name
            conf.connectionTimeout = 30.0
            conf.onStateChanged = onStateChanged
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

    if BOOTSTRAP_ITERATIONS is not None:
        print(Fore.YELLOW + f'[{node_name}] Bootstrap-election mode: '
              f'{BOOTSTRAP_ITERATIONS} rounds requested.')

        def _handle_sigterm_bootstrap(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, _handle_sigterm_bootstrap)

        completed = 0
        try:
            for round_num in range(1, BOOTSTRAP_ITERATIONS + 1):
                _election_start[0] = None
                print(Fore.CYAN + f'[{node_name}] Round {round_num}/'
                      f'{BOOTSTRAP_ITERATIONS}: starting fresh cluster instance...')
                o = Raft(self_addr, partner_addrs, nodes, node_name)

                round_start = time.perf_counter()
                LEADER_WAIT_TIMEOUT = 30.0
                while o._getLeader() is None:
                    if time.perf_counter() - round_start > LEADER_WAIT_TIMEOUT:
                        print(Fore.RED + f'[{node_name}] Round {round_num}: '
                              f'no leader formed within {LEADER_WAIT_TIMEOUT:.0f}s — skipping round.')
                        break
                    time.sleep(0.1)
                else:
                    completed += 1

                o.destroy_synchronous()

                time.sleep(BOOTSTRAP_COOLDOWN)
        except KeyboardInterrupt:
            print(Fore.YELLOW + f'\n[{node_name}] Bootstrap sampling stopped early '
                  f'after {completed} completed rounds.')

        election_monitor.save_file('election_measurements')
        print(Fore.GREEN + f'[{node_name}] Saved {len(election_monitor._results_list)} '
              f'leader election measurements to election_measurements.csv')
        print(Fore.GREEN + f'[{node_name}] Bootstrap sampling done '
              f'({completed}/{BOOTSTRAP_ITERATIONS} rounds formed a leader).')
        sys.exit(0)

    o = Raft(self_addr, partner_addrs, nodes, node_name)
    
    latency_monitor = LatencyMonitor()   # baseline commit latency (closed-loop)

    # ── Wait for Raft to stabilise before sending ──────────────────────────
    print(Fore.YELLOW + f'[{node_name}] Waiting for leader election...')
    while o._getLeader() is None:
        time.sleep(1)
    print(Fore.GREEN + f'[{node_name}] Leader found — waiting 10s for network to stabilise...')
    time.sleep(10)
    # ───────────────────────────────────────────────────────────────────────

    print(Fore.GREEN + f'[{node_name}] Starting baseline (closed-loop) measurement...')
    print(Fore.YELLOW + f'[{node_name}] Running continuously — stop with Ctrl+C or `docker stop` when you have enough samples.')

    def _handle_sigterm(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _handle_sigterm)

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

        if outcome['err'] not in (None, FAIL_REASON.SUCCESS):
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

    seq = 0
    run_start = time.perf_counter()
    if RUN_DURATION_SECONDS is not None:
        print(Fore.YELLOW + f'[{node_name}] Will stop after {RUN_DURATION_SECONDS:.0f}s '
              f'of wall-clock time (Ctrl+C also still works).')
    try:
        while True:
            if RUN_DURATION_SECONDS is not None and (time.perf_counter() - run_start) >= RUN_DURATION_SECONDS:
                print(Fore.YELLOW + f'\n[{node_name}] Duration limit reached '
                      f'({RUN_DURATION_SECONDS:.0f}s) after {seq} samples. Stopping.')
                break
            while o._getLeader() is None:
                time.sleep(0.5)
            measure_commit_blocking(seq)
            seq += 1
    except KeyboardInterrupt:
        print(Fore.YELLOW + f'\n[{node_name}] Stopped after {seq} samples.')

    latency_monitor.save_file('commit_measurements')
    print(Fore.GREEN + f'[{node_name}] Saved {len(latency_monitor._results_list)} '
          f'baseline measurements to commit_measurements.csv')
    election_monitor.save_file('election_measurements')
    print(Fore.GREEN + f'[{node_name}] Saved {len(election_monitor._results_list)} '
          f'leader election measurements to election_measurements.csv')
    print(Fore.GREEN + f'[{node_name}] Done.')
