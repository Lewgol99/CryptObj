#!/usr/bin/env python3
# encoding: utf-8
import json
from seedemu import *
from seedemu.layers import Base, Routing, Ebgp, PeerRelationship, Ibgp, Ospf
from seedemu.services import WebService
from seedemu.core import Emulator
from seedemu.compiler import Docker

NUM_NODES    = 3
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
# Create Internet Exchange
ix100 = base.createInternetExchange(100)
Makers.makeTransitAs(base, 4, [100], [])
###############################################################################
as166 = base.createAutonomousSystem(166)
aac = AddressAssignmentConstraint(
    hostStart=10, hostEnd=60000, hostStep=1,
    dhcpStart=60001, dhcpEnd=60100,
    routerStart=65000, routerEnd=60200, routerStep=-1
)
as166.createNetwork('net0', prefix='10.166.0.0/16', aac=aac)
router0 = as166.createRealWorldRouter('router0', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router0.joinNetwork('ix100', '10.100.0.166')
router0.joinNetwork('net0', '10.166.0.2')
###############################################################################
ebgp.addRsPeers(100, [4])
ebgp.addPrivatePeerings(100, [4], [166], PeerRelationship.Provider)
###############################################################################
# Build nodes json
import base64
nodes = {}
for i in range(1, NUM_NODES + 1):
    nodes[f'node{i}'] = {'addr': f'10.166.{(i-1) // 254}.{i + 9}', 'port': 45025}
nodes_json = json.dumps(nodes)
nodes_b64  = base64.b64encode(nodes_json.encode()).decode()
# Write pretty local copy
with open('scale_nodes.json', 'w') as f:
    json.dump(nodes, f, indent=4)
build_cmd = f"python3 -c \"import json,base64; data=json.loads(base64.b64decode('{nodes_b64}').decode()); [open('/CryptObj/'+n,'w').write(json.dumps(data,indent=4)) for n in ['scale_nodes.json','nodes.json']]\""
###############################################################################
# CA node — static IP on net0
ca_host = (as166
           .createHost('ca_node')
           .joinNetwork('net0', address='10.166.0.253'))
ca_host.addSoftware('git')
ca_host.addSoftware('python3')
ca_host.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/CryptObj.git')
ca_host.addBuildCommand('find CryptObj -mindepth 2 -type f -exec mv -n {} CryptObj/ \\; || true')
ca_host.addBuildCommand('chmod -R 777 CryptObj')
ca_host.addBuildCommand(build_cmd)
ca_host.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
ca_host.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')
ca_host.addBuildCommand('cp CryptObj/transport.py /usr/local/lib/python3.8/dist-packages/pysyncobj/transport.py')
ca_host.addBuildCommand('cp CryptObj/encryptor.py /usr/local/lib/python3.8/dist-packages/pysyncobj/encryptor.py')
ca_host.appendStartCommand('until ip route | grep -q "10.166.0.0"; do sleep 1; done')
ca_host.appendStartCommand('cd /CryptObj && gunicorn --workers 32 --timeout 120 --bind 0.0.0.0:5000 ca_server:app')
###############################################################################
# All nodes on net0
for i in range(1, NUM_NODES + 1):
    name = f'node{i:03d}'
    host = as166.createHost(name).joinNetwork('net0')
    host.addSoftware('git')
    host.addSoftware('python3')
    host.addBuildCommand(f'git clone https://{GIT_USERNAME}:{GIT_TOKEN}@github.com/Lewgol99/CryptObj.git')
    host.addBuildCommand('find CryptObj -mindepth 2 -type f -exec mv -n {} CryptObj/ \\; || true')
    host.addBuildCommand('chmod -R 777 CryptObj')
    host.addBuildCommand(build_cmd)
    host.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
    host.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')
    host.addBuildCommand('cp CryptObj/transport.py /usr/local/lib/python3.8/dist-packages/pysyncobj/transport.py')
    host.addBuildCommand('cp CryptObj/encryptor.py /usr/local/lib/python3.8/dist-packages/pysyncobj/encryptor.py')
    host.appendStartCommand('until ip route | grep -q "10.166.0.0"; do sleep 1; done')
    host.appendStartCommand(f'cd /CryptObj && python3 /CryptObj/scale_cryptobj.py node{i} RSA 2048 AES')
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
