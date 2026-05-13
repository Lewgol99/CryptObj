#!/usr/bin/env python3
# encoding: utf-8
import json
from seedemu import *
from seedemu.layers import Base, Routing, Ebgp, PeerRelationship, Ibgp, Ospf
from seedemu.services import WebService
from seedemu.core import Emulator
from seedemu.compiler import Docker

NUM_NODES    = 50
GIT_USERNAME = 'Lewgol99'
GIT_TOKEN    = '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'
GIT_REPO     = 'https://github.com/Lewgol99/CryptObj.git'

###############################################################################
emu     = Emulator()
base    = Base()
routing = Routing()
ebgp    = Ebgp()
ibgp    = Ibgp()
ospf    = Ospf()
web     = WebService()
###############################################################################
# Internet Exchanges
ix100 = base.createInternetExchange(100)
ix101 = base.createInternetExchange(101)
ix100.getPeeringLan().setDisplayName('Bank-100')
ix101.getPeeringLan().setDisplayName('Bank-101')
###############################################################################
# Tier 1
Makers.makeTransitAs(base, 4, [100, 101], [(101, 100)])
###############################################################################
NETWORK_ASES = [166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183]
NODES_PER_NET = NUM_NODES // len(NETWORK_ASES)
as_objects = {}

for asn in NETWORK_ASES:
    asobj = base.createAutonomousSystem(asn)
    asobj.createNetwork('net0')
    as_objects[asn] = asobj

    router = asobj.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
    router.joinNetwork('net0')
    router.joinNetwork('ix100')   # All ASes peer at ix100

###############################################################################
# Build nodes json
nodes = {}
for i in range(NUM_NODES):
    asn = NETWORK_ASES[i % len(NETWORK_ASES)]
    nodes[f'node{i+1}'] = {'asn': asn, 'port': 45025}
nodes_json = json.dumps(nodes)

###############################################################################
# CA node — lives in AS166, static IP, runs ca_server.py on startup
ca_host = (as_objects[166]
           .createHost('ca_node')
           .joinNetwork('net0', address='10.166.0.100'))
ca_host.addSoftware('git')
ca_host.addSoftware('python3')
ca_host.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/CryptObj.git')
ca_host.addBuildCommand('chmod -R 777 CryptObj')
ca_host.addBuildCommand(f'python3 -c "import json; open(\'CryptObj/scale_nodes.json\',\'w\').write(\'{nodes_json}\')"')
ca_host.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
ca_host.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')
ca_host.addBuildCommand('cp CryptObj/src/transport.py /usr/local/lib/python3.8/dist-packages/pysyncobj/transport.py')
ca_host.addBuildCommand('cp CryptObj/src/encryptor.py /usr/local/lib/python3.8/dist-packages/pysyncobj/encryptor.py')
ca_host.appendStartCommand('python3 /CryptObj/CA/ca_server.py')

###############################################################################
# Regular nodes
for i in range(NUM_NODES):
    asn   = NETWORK_ASES[i % len(NETWORK_ASES)]
    asobj = as_objects[asn]
    name  = f'node{i:03d}'
    host  = asobj.createHost(name).joinNetwork('net0')
    host.addSoftware('git')
    host.addSoftware('python3')
    host.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/CryptObj.git')
    host.addBuildCommand('chmod -R 777 CryptObj')
    host.addBuildCommand(f'python3 -c "import json; open(\'CryptObj/scale_nodes.json\',\'w\').write(\'{nodes_json}\')"')
    host.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
    host.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')
    host.addBuildCommand('cp CryptObj/src/transport.py /usr/local/lib/python3.8/dist-packages/pysyncobj/transport.py')
    host.addBuildCommand('cp CryptObj/src/encryptor.py /usr/local/lib/python3.8/dist-packages/pysyncobj/encryptor.py')

###############################################################################
# Peering — AS4 is the transit provider for all network ASes at ix100
ebgp.addRsPeers(100, [4])                                          # AS4 peers with route server
ebgp.addPrivatePeerings(100, [4], NETWORK_ASES, PeerRelationship.Provider)  # AS4 provides transit to all
ebgp.addRsPeers(101, [4])

###############################################################################
emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(ebgp)
emu.addLayer(ibgp)
emu.addLayer(ospf)
emu.addLayer(web)
emu.dump('base-component.bin')
emu.render()
emu.compile(Docker(), './output', override=True)
