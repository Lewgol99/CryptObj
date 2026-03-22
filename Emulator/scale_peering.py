from seedemu.core import Emulator
from seedemu.layers import Base, Routing, Ebgp
from seedemu.compiler import Docker

NUM_NODES = 50

emu  = Emulator()
base = Base()

base.createInternetExchange(100)

as150 = base.createAutonomousSystem(150)

as150.createNetwork('net0')
as150.createNetwork('net1')
as150.createNetwork('net2')

router = as150.createRouter('router0')
router.joinNetwork('ix100')
router.joinNetwork('net0')
router.joinNetwork('net1')
router.joinNetwork('net2')

nets = ['net0', 'net1', 'net2']

for i in range(NUM_NODES):
    host = as150.createHost(f'host{i}')
    host.joinNetwork(nets[i % len(nets)])

emu.addLayer(base)
emu.addLayer(Routing())
emu.addLayer(Ebgp())
emu.render()
emu.compile(Docker(), './output')
