#!/usr/bin/env python3
# encoding: utf-8
from seedemu import *
from seedemu.layers import Base, Routing, Ebgp, PeerRelationship, Ibgp, Ospf
from seedemu.services import WebService
from seedemu.core import Emulator
from seedemu.compiler import Docker

NUM_NODES = 50

GIT_USERNAME = 'Lewgol99'
GIT_TOKEN = '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'
GIT_REPO  = 'https://github.com/Lewgol99/PySyncCryptObj.git'

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
# Dynamically create branch ASes
branch_asns = []
for i in range(NUM_NODES):
    asn = 166 + (i * 10)
    branch_asns.append(asn)
    asobj  = base.createAutonomousSystem(asn)
    router = asobj.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
    router.joinNetwork('ix100', f'10.100.0.{asn % 256}')
    router.addSoftware('git')
    router.addSoftware('python3')
    router.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/PySyncCryptObj.git')
    router.addBuildCommand(f'chmod -R 777 PySyncCryptObj')

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
