#!/usr/bin/env python3
# encoding: utf-8

import random
import os

# Import the SEED Library
from seedemu import *
from seedemu.layers import Base, Routing, Ebgp, PeerRelationship, Ibgp, Ospf
from seedemu.services import WebService
from seedemu.core import Emulator, Binding, Filter, Action
from seedemu.compiler import Docker
from seedemu.services import BotnetService, BotnetClientService

###############################################################################

# Emulator Setup
emu = Emulator()
base = Base()
routing = Routing()
ebgp = Ebgp()
ibgp = Ibgp()
ospf = Ospf()
web = WebService()
bot = BotnetService()
botClient = BotnetClientService()

###############################################################################
# Create the network topology first

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
as166.createNetwork('net0') # create net 0
as166.createNetwork('net1') # create net 1
as166.createNetwork('net2') # create net 2
as166.createNetwork('net3') # create net 3
as166.createNetwork('net4') # create net 4
as166.createNetwork('net5') # create net 5
as166.createNetwork('net6') # create net 6
as166.createNetwork('net7') # create net 7
as166.createNetwork('net8') # create net 8
as166.createNetwork('net9') # create net 9
as166.createNetwork('net10') # create net 10
as166.createHost('host0').joinNetwork('net0')
router166 = as166.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router166.addSoftware('git')
router166.addSoftware('python3')
router166.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/PySyncCryptObj.git')
router166.addBuildCommand(f'chmod -R 777 PySyncCryptObj')
router166.joinNetwork('net0') # join net 0
router166.joinNetwork('net1') # join net 1
router166.joinNetwork('net2') # join net 2
router166.joinNetwork('net3') # join net 3
router166.joinNetwork('net4') # join net 4
router166.joinNetwork('net5') # join net 5
router166.joinNetwork('net6') # join net 6
router166.joinNetwork('net7') # join net 7
router166.joinNetwork('net8') # join net 8
router166.joinNetwork('net9') # join net 9
router166.joinNetwork('net10') # join net 10
router166.joinNetwork('ix100', '10.100.0.166') # TX-PBAC Node

# AS176
as176 = base.createAutonomousSystem(176)
as176.createNetwork('net0') # create net 0
as176.createNetwork('net1') # create net 1
as176.createNetwork('net2') # create net 2
as176.createNetwork('net3') # create net 3
as176.createNetwork('net4') # create net 4
as176.createNetwork('net5') # create net 5
as176.createNetwork('net6') # create net 6
as176.createNetwork('net7') # create net 7
as176.createNetwork('net8') # create net 8
as176.createNetwork('net9') # create net 9
as176.createHost('host0').joinNetwork('net0')
router176 = as176.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router176.addSoftware('git')
router176.addSoftware('python3')
router176.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/PySyncCryptObj.git')
router176.addBuildCommand(f'chmod -R 777 PySyncCryptObj')
router176.joinNetwork('net0') # join net 0
router176.joinNetwork('net1') # join net 1
router176.joinNetwork('net2') # join net 2
router176.joinNetwork('net3') # join net 3
router176.joinNetwork('net4') # join net 4
router176.joinNetwork('net5') # join net 5
router176.joinNetwork('net6') # join net 6
router176.joinNetwork('net7') # join net 7
router176.joinNetwork('net8') # join net 8
router176.joinNetwork('net9') # join net 9
router176.joinNetwork('ix100', '10.100.0.176') # TX-PBAC Node
router176.addSoftware('git')
router176.addSoftware('python3')

# AS186
as186 = base.createAutonomousSystem(186)
as186.createNetwork('net0') # create net 0
as186.createNetwork('net1') # create net 1
as186.createNetwork('net2') # create net 2
as186.createNetwork('net3') # create net 3
as186.createNetwork('net4') # create net 4
as186.createNetwork('net5') # create net 5
as186.createNetwork('net6') # create net 6
as186.createNetwork('net7') # create net 7
as186.createNetwork('net8') # create net 8
as186.createNetwork('net9') # create net 9
as186.createHost('host0').joinNetwork('net0')
router186 = as186.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router186.addSoftware('git')
router186.addSoftware('python3')
router186.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/PySyncCryptObj.git')
router186.addBuildCommand(f'chmod -R 777 PySyncCryptObj')
router186.joinNetwork('net0') # join net 0
router186.joinNetwork('net1') # join net 1
router186.joinNetwork('net2') # join net 2
router186.joinNetwork('net3') # join net 3
router186.joinNetwork('net4') # join net 4
router186.joinNetwork('net5') # join net 5
router186.joinNetwork('net6') # join net 6
router186.joinNetwork('net7') # join net 7
router186.joinNetwork('net8') # join net 8
router186.joinNetwork('net9') # join net 9
router186.joinNetwork('ix100', '10.100.0.186') # TX-PBAC Node
router186.addSoftware('git')
router186.addSoftware('python3')

# AS196
as196 = base.createAutonomousSystem(196)
as196.createNetwork('net0') # create net 0
as196.createNetwork('net1') # create net 1
as196.createNetwork('net2') # create net 2
as196.createNetwork('net3') # create net 3
as196.createNetwork('net4') # create net 4
as196.createNetwork('net5') # create net 5
as196.createNetwork('net6') # create net 6
as196.createNetwork('net7') # create net 7
as196.createNetwork('net8') # create net 8
as196.createNetwork('net9') # create net 9
as196.createHost('host0').joinNetwork('net0')
router196 = as196.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router196.addSoftware('git')
router196.addSoftware('python3')
router196.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/PySyncCryptObj.git')
router196.addBuildCommand(f'chmod -R 777 PySyncCryptObj')
router196.joinNetwork('net0') # join net 0
router196.joinNetwork('net1') # join net 1
router196.joinNetwork('net2') # join net 2
router196.joinNetwork('net3') # join net 3
router196.joinNetwork('net4') # join net 4
router196.joinNetwork('net5') # join net 5
router196.joinNetwork('net6') # join net 6
router196.joinNetwork('net7') # join net 7
router196.joinNetwork('net8') # join net 8
router196.joinNetwork('net9') # join net 9
router196.joinNetwork('ix100', '10.100.0.196') # TX-PBAC Node
router196.addSoftware('git')
router196.addSoftware('python3')

###############################################################################
# Set up BGP peering

ebgp.addRsPeers(100, [4])
ebgp.addPrivatePeerings(100, [4], [166, 176, 186, 196], PeerRelationship.Provider)

###############################################################################
# Now add the botnet components

# Create bot controller
bot.install('bot-controller')
emu.getVirtualNode('bot-controller').setDisplayName('Bot-Controller')

# Install DDoS script on controller
if os.path.exists("./ddos.py"):
    with open("./ddos.py", "r") as f:
        emu.getVirtualNode('bot-controller').setFile(content=f.read(), path="/tmp/ddos.py")
else:
    print("Warning: ddos.py not found")

# Create bot nodes
num_bots = 250
for counter in range(num_bots):
    vname = f'bot-node-{counter:03d}'
    botClient.install(vname).setServer('bot-controller')
    emu.getVirtualNode(vname).setDisplayName(f'Bot-{counter:03d}')

###############################################################################
# Bind botnet nodes to the network

# Define your available ASes
available_as_list = [166, 176, 186, 196]

# Bind controller to one of your ASes
emu.addBinding(Binding('bot-controller', 
               filter=Filter(asn=166), action=Action.NEW))

# Distribute bots across your ASes
for counter in range(num_bots):
    vname = f'bot-node-{counter:03d}'
    asn = random.choice(available_as_list)
    emu.addBinding(Binding(vname, filter=Filter(asn=asn), action=Action.NEW))

###############################################################################
# Add all layers to the emulator

emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(ebgp)
emu.addLayer(ibgp)
emu.addLayer(ospf)
emu.addLayer(web)
emu.addLayer(bot)
emu.addLayer(botClient)

###############################################################################

emu.dump('base_tx-pbac.bin')
emu.render()
emu.compile(Docker(), './output', override=True)
