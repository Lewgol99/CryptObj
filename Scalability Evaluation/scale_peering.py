#!/usr/bin/env python3
# encoding: utf-8
from seedemu import *
from seedemu.layers import Base, Routing, Ebgp, PeerRelationship, Ibgp, Ospf
from seedemu.services import WebService
from seedemu.core import Emulator
from seedemu.compiler import Docker
import json

NUM_NODES = 50
GIT_USERNAME = 'Lewgol99'
GIT_TOKEN = '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'
GIT_REPO  = 'https://github.com/Lewgol99/CryptObj.git'

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
# Build nodes dict first with safe sequential IPs
nodes = {}
for i in range(NUM_NODES):
    asn = 166 + i
    offset = 10 + i
    ip = f'10.100.{offset // 256}.{offset % 256}'
    nodes[f'node{i+1}'] = {'addr': ip, 'port': 45025}
nodes_json = json.dumps(nodes)
###############################################################################
# Dynamically create branch ASes
branch_asns = []
for i in range(NUM_NODES):
    asn = 166 + i
    branch_asns.append(asn)
    offset = 10 + i
    ip = f'10.100.{offset // 256}.{offset % 256}'
    asobj  = base.createAutonomousSystem(asn)
    router = asobj.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
    router.joinNetwork('ix100', ip)
    router.addSoftware('git')
    router.addSoftware('python3')
    router.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/CryptObj.git')
    router.addBuildCommand(f'chmod -R 777 CryptObj')
    router.addBuildCommand(f'python3 -c "import json; data={nodes}; open(\'CryptObj/scale_nodes.json\',\'w\').write(json.dumps(data, indent=4))"')
    router.addBuildCommand('apt-get install -y lftp python3-pip')
    router.addBuildCommand('pip3 install -r CryptObj/requirements.txt')
###############################################################################
# Peering
ebgp.addRsPeers(100, [4])
ebgp.addPrivatePeerings(100, [4], branch_asns, PeerRelationship.Provider)
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
