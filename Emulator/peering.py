#!/usr/bin/env python3
# encoding: utf-8

# Import the SEED Library
from seedemu import *
from seedemu.layers import Base, Routing, Ebgp, PeerRelationship, Ibgp, Ospf
from seedemu.services import WebService
from seedemu.core import Emulator
from seedemu.compiler import Docker

###############################################################################

# Emulator Setup
emu = Emulator()
base = Base()
routing = Routing()
ebgp = Ebgp()
ibgp = Ibgp()
ospf = Ospf()
web = WebService()

###############################################################################

# Create Internet Exchanges
ix100 = base.createInternetExchange(100)
ix101 = base.createInternetExchange(101)

ix100.getPeeringLan().setDisplayName('Bank-100')
ix101.getPeeringLan().setDisplayName('Bank-101')

###############################################################################

# Tier 1 ASes
Makers.makeTransitAs(base, 4, [100, 101], [(101, 100)])

###############################################################################

# AS166
as166 = base.createAutonomousSystem(166)
router166 = as166.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router166.joinNetwork('ix100', '10.100.0.166')
router166.addSoftware('git')
router166.addSoftware('python3')
router166.addBuildCommand('git clone https://Lewis_Golightly:glpat-JYlJFrTOHelHjmyr9z_WiW86MQp1Ojlkcm0xCw.01.1207pf6j2@gitlab.com/phd_team/tlxpp-pbac.git')
router166.appendStartCommand('chmod -R 777 tlxpp-pbac')
router166.appendStartCommand('cd tlxpp-pbac')
router166.appendStartCommand('find . -mindepth 2 -type f -exec mv -t . {} +')

# AS176
as176 = base.createAutonomousSystem(176)
router176 = as176.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router176.joinNetwork('ix100', '10.100.0.176')
router176.addSoftware('git')
router176.addSoftware('python3')
router176.addBuildCommand('git clone https://Lewis_Golightly:glpat-JYlJFrTOHelHjmyr9z_WiW86MQp1Ojlkcm0xCw.01.1207pf6j2@gitlab.com/phd_team/tlxpp-pbac.git')
router176.appendStartCommand('chmod -R 777 tlxpp-pbac')
router176.appendStartCommand('cd tlxpp-pbac')
router176.appendStartCommand('find . -mindepth 2 -type f -exec mv -t . {} +')

# AS186
as186 = base.createAutonomousSystem(186)
router186 = as186.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router186.joinNetwork('ix100', '10.100.0.186')
router186.addSoftware('git')
router186.addSoftware('python3')
router186.addBuildCommand('git clone https://Lewis_Golightly:glpat-JYlJFrTOHelHjmyr9z_WiW86MQp1Ojlkcm0xCw.01.1207pf6j2@gitlab.com/phd_team/tlxpp-pbac.git')
router186.appendStartCommand('chmod -R 777 tlxpp-pbac')
router186.appendStartCommand('cd tlxpp-pbac')
router186.appendStartCommand('find . -mindepth 2 -type f -exec mv -t . {} +')

# AS196
as196 = base.createAutonomousSystem(196)
router196 = as196.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router196.joinNetwork('ix100', '10.100.0.196')
router196.addSoftware('git')
router196.addSoftware('python3')
router196.addBuildCommand('git clone https://Lewis_Golightly:glpat-JYlJFrTOHelHjmyr9z_WiW86MQp1Ojlkcm0xCw.01.1207pf6j2@gitlab.com/phd_team/tlxpp-pbac.git')
router196.appendStartCommand('chmod -R 777 tlxpp-pbac')
router196.appendStartCommand('cd tlxpp-pbac')
router196.appendStartCommand('find . -mindepth 2 -type f -exec mv -t . {} +')

###############################################################################

# Peering
ebgp.addRsPeers(100, [4])
ebgp.addPrivatePeerings(100, [4], [166, 176, 186, 196], PeerRelationship.Provider)

###############################################################################

# Add layers
emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(ebgp)
emu.addLayer(ibgp)
emu.addLayer(ospf)
emu.addLayer(web)

###############################################################################

emu.dump('base-component.bin')
emu.render()
emu.compile(Docker(), './output', override=True)
