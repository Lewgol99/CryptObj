from seedemu import *
from seedemu.layers import Base, Routing, Ebgp, PeerRelationship, Ibgp, Ospf
from seedemu.services import WebService
from seedemu.core import Emulator
from seedemu.compiler import Docker

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
router166.addBuildCommand(f'git clone https://github.com/Lewgol99/CryptObj.git')
router166.addBuildCommand(f'chmod -R 777 CryptObj')
router166.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
router166.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')

# AS176
as176 = base.createAutonomousSystem(176)
router176 = as176.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router176.joinNetwork('ix100', '10.100.0.176')
router176.addSoftware('git')
router176.addSoftware('python3')
router176.addBuildCommand(f'git clone https://github.com/Lewgol99/CryptObj.git')
router176.addBuildCommand(f'chmod -R 777 CryptObj')
router176.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
router176.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')

# AS186
as186 = base.createAutonomousSystem(186)
router186 = as186.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router186.joinNetwork('ix100', '10.100.0.186')
router186.addSoftware('git')
router186.addSoftware('python3')
router186.addBuildCommand(f'git clone https://github.com/Lewgol99/CryptObj.git')
router186.addBuildCommand(f'chmod -R 777 CryptObj')
router186.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
router186.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')

# AS196
as196 = base.createAutonomousSystem(196)
router196 = as196.createRealWorldRouter('branch', prefixes=['0.0.0.0/1', '128.0.0.0/1'])
router196.joinNetwork('ix100', '10.100.0.196')
router196.addSoftware('git')
router196.addSoftware('python3')
router196.addBuildCommand(f'git clone https://github.com/Lewgol99/CryptObj.git')
router196.addBuildCommand(f'chmod -R 777 CryptObj')
router196.addBuildCommand('apt-get install -y --no-install-recommends lftp python3-pip && apt-get clean && rm -rf /var/lib/apt/lists/*')
router196.addBuildCommand('pip3 install --no-cache-dir -r CryptObj/requirements.txt')
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
