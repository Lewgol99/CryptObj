from .config import FAIL_REASON
from .dns_resolver import globalDnsResolver
from .monotonic import monotonic as monotonicTime
from .node import Node, TCPNode
from .tcp_connection import TcpConnection, CONNECTION_STATE
from .tcp_server import TcpServer
import functools
import os
import threading
import time
import random
from digital_signature import DigitalSignature
from colorama import Fore

class TransportNotReadyError(Exception):
    """Transport failed to get ready for operation."""


class Transport(object):
    """Base class for implementing a transport between PySyncObj nodes"""

    def __init__(self, syncObj, selfNode, otherNodes):
        self._onMessageReceivedCallback = None
        self._onNodeConnectedCallback = None
        self._onNodeDisconnectedCallback = None
        self._onReadonlyNodeConnectedCallback = None
        self._onReadonlyNodeDisconnectedCallback = None
        self._onUtilityMessageCallbacks = {}

    def setOnMessageReceivedCallback(self, callback):
        self._onMessageReceivedCallback = callback

    def setOnNodeConnectedCallback(self, callback):
        self._onNodeConnectedCallback = callback

    def setOnNodeDisconnectedCallback(self, callback):
        self._onNodeDisconnectedCallback = callback

    def setOnReadonlyNodeConnectedCallback(self, callback):
        self._onReadonlyNodeConnectedCallback = callback

    def setOnReadonlyNodeDisconnectedCallback(self, callback):
        self._onReadonlyNodeDisconnectedCallback = callback

    def setOnUtilityMessageCallback(self, message, callback):
        if callback:
            self._onUtilityMessageCallbacks[message] = callback
        elif message in self._onUtilityMessageCallbacks:
            del self._onUtilityMessageCallbacks[message]

    def _onMessageReceived(self, node, message):
        if self._onMessageReceivedCallback is not None:
            self._onMessageReceivedCallback(node, message)

    def _onNodeConnected(self, node):
        if self._onNodeConnectedCallback is not None:
            self._onNodeConnectedCallback(node)

    def _onNodeDisconnected(self, node):
        if self._onNodeDisconnectedCallback is not None:
            self._onNodeDisconnectedCallback(node)

    def _onReadonlyNodeConnected(self, node):
        if self._onReadonlyNodeConnectedCallback is not None:
            self._onReadonlyNodeConnectedCallback(node)

    def _onReadonlyNodeDisconnected(self, node):
        if self._onReadonlyNodeDisconnectedCallback is not None:
            self._onReadonlyNodeDisconnectedCallback(node)

    def tryGetReady(self):
        pass

    @property
    def ready(self):
        return True

    def waitReady(self):
        pass

    def addNode(self, node):
        pass

    def dropNode(self, node):
        pass

    def send(self, node, message):
        raise NotImplementedError

    def destroy(self):
        pass


class TCPTransport(Transport):
    def __init__(self, syncObj, selfNode, otherNodes):
        super(TCPTransport, self).__init__(syncObj, selfNode, otherNodes)
        self.signer = DigitalSignature()
        self.signer.Load_Private_Key()
        self._syncObj = syncObj
        self._server = None
        self._connections = {}
        self._unknownConnections = set()
        self._selfNode = selfNode
        self._selfIsReadonlyNode = selfNode is None
        self._nodes = set()
        self._readonlyNodes = set()
        self._nodeAddrToNode = {}
        self._lastConnectAttempt = {}
        self._preventConnectNodes = set()
        self._readonlyNodesCounter = 0
        self._lastBindAttemptTime = 0
        self._bindAttempts = 0
        self._bindOverEvent = threading.Event()
        self._ready = False
        self._send_random_sleep_duration = 0

        self._syncObj.addOnTickCallback(self._onTick)

        for node in otherNodes:
            self.addNode(node)

        if not self._selfIsReadonlyNode:
            self._createServer()
        else:
            self._ready = True

    def _connToNode(self, conn):
        for node in self._connections:
            if self._connections[node] is conn:
                return node
        return None

    def tryGetReady(self):
        self._maybeBind()

    @property
    def ready(self):
        return self._ready

    def _createServer(self):
        conf = self._syncObj.conf
        bindAddr = conf.bindAddress
        seflAddr = getattr(self._selfNode, 'address')
        if bindAddr is not None:
            host, port = bindAddr.rsplit(':', 1)
        elif seflAddr is not None:
            host, port = seflAddr.rsplit(':', 1)
            if ':' in host:
                host = '::'
            else:
                host = '0.0.0.0'
        else:
            raise RuntimeError('Unable to determine bind address')

        if host != '0.0.0.0':
            host = globalDnsResolver().resolve(host)
        self._server = TcpServer(self._syncObj._poller, host, port, onNewConnection=self._onNewIncomingConnection,
                                 sendBufferSize=conf.sendBufferSize,
                                 recvBufferSize=conf.recvBufferSize,
                                 connectionTimeout=conf.connectionTimeout)

    def _maybeBind(self):
        if self._ready or self._selfIsReadonlyNode or monotonicTime() < self._lastBindAttemptTime + self._syncObj.conf.bindRetryTime:
            return
        self._lastBindAttemptTime = monotonicTime()
        try:
            self._server.bind()
        except Exception as e:
            self._bindAttempts += 1
            if self._syncObj.conf.maxBindRetries and self._bindAttempts >= self._syncObj.conf.maxBindRetries:
                self._bindOverEvent.set()
                raise TransportNotReadyError
        else:
            self._ready = True
            self._bindOverEvent.set()

    def _onTick(self):
        try:
            self._maybeBind()
        except TransportNotReadyError:
            pass
        self._connectIfNecessary()

    def _onNewIncomingConnection(self, conn):
        self._unknownConnections.add(conn)
        encryptor = self._syncObj.encryptor
        if encryptor:
            conn.encryptor = encryptor
        conn.setOnMessageReceivedCallback(functools.partial(self._onIncomingMessageReceived, conn))
        conn.setOnDisconnectedCallback(functools.partial(self._onDisconnected, conn))

    def _onIncomingMessageReceived(self, conn, message):
        if isinstance(message, list) and self._onUtilityMessage(conn, message):
            return

        if isinstance(message, dict) and message.get('type') == 'handshake':
            peer_node_name = message.get('node_name')
            peer_cert = message.get('certificate')
            peer_address = message.get('address')

            if peer_cert and peer_node_name:
                signature = message.get('signature')
                signing_key_pem = message.get('signing_public_key')
                peer_public_key = self.signer.load_public_key_from_pem(signing_key_pem)
                if not self.signer.validate(peer_public_key, peer_cert.encode(), signature):
                    print(Fore.RED + f'Error: {peer_node_name} Failed Authentication!')
                    conn.disconnect()
                    return
                print(Fore.GREEN + f'Success: {peer_node_name} Authenticated!')

            if peer_cert and peer_node_name:
                try:
                    with open(f'{peer_node_name}_certificate.pem', 'w') as f:
                        f.write(peer_cert)
                    print(Fore.YELLOW + f"[INCOMING] Received and saved certificate from {peer_node_name}")

                    if self._syncObj.encryptor:
                        self._syncObj.encryptor._load_certificates()

                    # Broadcast our cert to all other connected nodes
                    self._broadcastCertificate(exclude_conn=conn)

                except Exception as e:
                    print(Fore.YELLOW + f"[INCOMING] Failed to save certificate from {peer_node_name}: {e}")

            self._sendSelfAddress(conn)
            message = peer_address

        node = self._nodeAddrToNode[message] if message in self._nodeAddrToNode else None

        if node is None and message != 'readonly':
            conn.disconnect()
            self._unknownConnections.discard(conn)
            return

        readonly = node is None
        if readonly:
            nodeId = str(self._readonlyNodesCounter)
            node = Node(nodeId)
            self._readonlyNodes.add(node)
            self._readonlyNodesCounter += 1

        self._unknownConnections.discard(conn)
        self._connections[node] = conn

        conn.setOnMessageReceivedCallback(functools.partial(self._onMessageReceived, node))

        if not readonly:
            self._onNodeConnected(node)
        else:
            self._onReadonlyNodeConnected(node)

    def _onUtilityMessage(self, conn, message):
        command = message[0]
        if command in self._onUtilityMessageCallbacks:
            message[0] = command.upper()
            callback = functools.partial(self._utilityCallback, conn=conn, args=message)
            try:
                self._onUtilityMessageCallbacks[command](message[1:], callback)
            except Exception as e:
                conn.send(str(e))
            return True

    def _utilityCallback(self, res, err, conn, args):
        if not (err is None and res):
            cmdResult = 'SUCCESS' if err == FAIL_REASON.SUCCESS else 'FAIL'
            res = ' '.join(map(str, [cmdResult] + args))
        conn.send(res)

    def _shouldConnect(self, node):
        return isinstance(node, TCPNode) and node not in self._preventConnectNodes and (self._selfIsReadonlyNode or self._selfNode.address > node.address)

    def _connectIfNecessarySingle(self, node):
        if node in self._connections and self._connections[node].state != CONNECTION_STATE.DISCONNECTED:
            return True
        if not self._shouldConnect(node):
            return False
        assert node in self._connections
        if node in self._lastConnectAttempt and monotonicTime() - self._lastConnectAttempt[node] < self._syncObj.conf.connectionRetryTime:
            return False
        self._lastConnectAttempt[node] = monotonicTime()
        return self._connections[node].connect(node.ip, node.port)

    def _connectIfNecessary(self):
        for node in self._nodes:
            self._connectIfNecessarySingle(node)

    def _broadcastCertificate(self, exclude_conn=None):
        """Send our certificate to all connected nodes except the one we just received from."""
        for node, conn in self._connections.items():
            if conn is not exclude_conn and conn.state == CONNECTION_STATE.CONNECTED:
                try:
                    self._sendSelfAddress(conn)
                except Exception as e:
                    print(Fore.YELLOW + f"[BROADCAST] Failed to send cert to {node}: {e}")

    def _sendSelfAddress(self, conn):
        node_name = getattr(self._syncObj.conf, 'node_name', None)
        our_cert = None
        signing_public_key = None

        try:
            with open('signing_public_key.pem', 'r') as file:
                signing_public_key = file.read()
        except FileNotFoundError:
            signing_public_key = None

        try:
            if node_name:
                with open(f'{node_name}_certificate.pem', 'r') as f:
                    our_cert = f.read()
            else:
                with open('certificate.pem', 'r') as f:
                    our_cert = f.read()
        except FileNotFoundError:
            print(Fore.YELLOW + f"Warning: Certificate file not found for {node_name}")

        signature = self.signer.sign(our_cert.encode())

        if self._selfIsReadonlyNode:
            conn.send({'type': 'handshake', 'node_name': node_name, 'address': 'readonly', 'certificate': our_cert, 'signature': signature, 'signing_public_key': signing_public_key})
        else:
            conn.send({'type': 'handshake', 'node_name': node_name, 'address': self._selfNode.address, 'certificate': our_cert, 'signature': signature, 'signing_public_key': signing_public_key})

    def _onOutgoingConnected(self, conn):
        conn.setOnMessageReceivedCallback(functools.partial(self._onOutgoingHandshakeResponse, conn))
        self._sendSelfAddress(conn)

    def _onOutgoingHandshakeResponse(self, conn, message):
        if isinstance(message, dict) and message.get('type') == 'handshake':
            peer_node_name = message.get('node_name')
            peer_cert = message.get('certificate')
            signature = message.get('signature')

            if peer_cert and peer_node_name and signature:
                signing_key_pem = message.get('signing_public_key')
                peer_public_key = self.signer.load_public_key_from_pem(signing_key_pem)
                if not self.signer.validate(peer_public_key, peer_cert.encode(), signature):
                    print(Fore.RED + f'Error: {peer_node_name} digital signature rejected and failed authentication!')
                    conn.disconnect()
                    return
                print(Fore.GREEN + f'Success: {peer_node_name} Digital Signature Authenticated!')

                try:
                    with open(f'{peer_node_name}_certificate.pem', 'w') as f:
                        f.write(peer_cert)
                    print(Fore.YELLOW + f"[OUTGOING] Received and saved certificate from {peer_node_name}")

                    if self._syncObj.encryptor:
                        self._syncObj.encryptor._load_certificates()

                    # Broadcast our cert to all other connected nodes
                    self._broadcastCertificate(exclude_conn=conn)

                except Exception as e:
                    print(Fore.YELLOW + f"[OUTGOING] Failed to save certificate from {peer_node_name}: {e}")
            else:
                print(Fore.YELLOW + f"[OUTGOING] Handshake missing certificate or node_name")

        node = self._connToNode(conn)
        conn.setOnMessageReceivedCallback(functools.partial(self._onMessageReceived, node))
        self._onNodeConnected(node)

    def _onDisconnected(self, conn):
        self._unknownConnections.discard(conn)
        node = self._connToNode(conn)
        if node is not None:
            if node in self._nodes:
                self._onNodeDisconnected(node)
                self._connectIfNecessarySingle(node)
            else:
                self._readonlyNodes.discard(node)
                self._onReadonlyNodeDisconnected(node)

    def waitReady(self):
        self._bindOverEvent.wait()
        if not self._ready:
            raise TransportNotReadyError

    def addNode(self, node):
        self._nodes.add(node)
        self._nodeAddrToNode[node.address] = node
        if self._shouldConnect(node):
            conn = TcpConnection(
                poller=self._syncObj._poller,
                timeout=self._syncObj.conf.connectionTimeout,
                sendBufferSize=self._syncObj.conf.sendBufferSize,
                recvBufferSize=self._syncObj.conf.recvBufferSize,
                keepalive=self._syncObj.conf.tcp_keepalive,
            )
            conn.encryptor = self._syncObj.encryptor
            conn.setOnConnectedCallback(functools.partial(self._onOutgoingConnected, conn))
            conn.setOnMessageReceivedCallback(functools.partial(self._onMessageReceived, node))
            conn.setOnDisconnectedCallback(functools.partial(self._onDisconnected, conn))
            self._connections[node] = conn

    def dropNode(self, node):
        conn = self._connections.pop(node, None)
        if conn is not None:
            self._preventConnectNodes.add(node)
            conn.disconnect()
            self._preventConnectNodes.remove(node)
        if isinstance(node, TCPNode):
            self._nodes.discard(node)
            self._nodeAddrToNode.pop(node.address, None)
        else:
            self._readonlyNodes.discard(node)
        self._lastConnectAttempt.pop(node, None)

    def send(self, node, message):
        if node not in self._connections or self._connections[node].state != CONNECTION_STATE.CONNECTED:
            return False
        if self._send_random_sleep_duration:
            time.sleep(random.random() * self._send_random_sleep_duration)
        self._connections[node].send(message)
        if self._connections[node].state != CONNECTION_STATE.CONNECTED:
            return False
        return True

    def destroy(self):
        self.setOnMessageReceivedCallback(None)
        self.setOnNodeConnectedCallback(None)
        self.setOnNodeDisconnectedCallback(None)
        self.setOnReadonlyNodeConnectedCallback(None)
        self.setOnReadonlyNodeDisconnectedCallback(None)
        for node in self._nodes | self._readonlyNodes:
            self.dropNode(node)
        if self._server is not None:
            self._server.unbind()
        for conn in list(self._unknownConnections):
            conn.disconnect()
        self._unknownConnections = set()
