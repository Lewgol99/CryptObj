from .config import FAIL_REASON
from .dns_resolver import globalDnsResolver
from .monotonic import monotonic as monotonicTime
from .node import Node, TCPNode
from .tcp_connection import TcpConnection, CONNECTION_STATE
from .tcp_server import TcpServer
import functools
import os
import pickle
import struct
import threading
import time
import random
from digital_signature import DigitalSignature
from colorama import Fore

class TransportNotReadyError(Exception):
    """Transport failed to get ready for operation."""

class Transport(object):

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


_FLAG_WAS_DICT = 0x01


def _wrap_and_sign(signer, message, sender_ip, recipient_ips):
    if isinstance(message, bytes):
        flags   = 0x00
        payload = message
    else:
        flags   = _FLAG_WAS_DICT
        payload = pickle.dumps(message)

    result = signer.sign(payload, sender_ip, recipient_ips)
    if result is None:
        print(Fore.YELLOW + '[SIGN] Signing failed — sending unsigned (sig_len=0)')
        signature      = b''
        signed_payload = payload
    else:
        signature, signed_payload = result

    header = struct.pack('!BH', flags, len(signature))
    return header + signature + signed_payload


def _unwrap_and_verify(signer, peer_public_key, raw):
    """Verify + deserialise a signed Raft message. Returns the original message object, or None on failure."""
    if len(raw) < 3:
        print(Fore.RED + '[VERIFY] Message too short to contain header')
        return None

    flags, sig_len = struct.unpack('!BH', raw[:3])

    if len(raw) < 3 + sig_len:
        print(Fore.RED + '[VERIFY] Message truncated inside signature')
        return None

    signature = raw[3:3 + sig_len]
    payload   = raw[3 + sig_len:]

    if peer_public_key is not None:
        if sig_len == 0:
            print(Fore.RED + '[VERIFY] No signature present but key exists — dropping!')
            return None
        if not signer.validate(peer_public_key, payload, signature):
            print(Fore.RED + '[VERIFY] Signature FAILED — dropping message!')
            return None
    else:
        print(Fore.YELLOW + '[VERIFY] No peer key stored — passing through unverified')

    # Strip the IP prefix (sender_ip,recipient,...||) that was prepended during signing
    sep_index = payload.find(b'||')
    if sep_index != -1:
        payload = payload[sep_index + 2:]

    if flags & _FLAG_WAS_DICT:
        try:
            return pickle.loads(payload)
        except Exception as e:
            print(Fore.RED + f'[VERIFY] pickle.loads failed: {e}')
            return None

    return payload


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
        self._peerSigningKeys = {}

        self._dbg_send_total    = 0
        self._dbg_send_signed   = 0
        self._dbg_recv_total    = 0
        self._dbg_recv_verified = 0
        self._dbg_recv_dropped  = 0

        self._syncObj.addOnTickCallback(self._onTick)

        for node in otherNodes:
            self.addNode(node)

        if not self._selfIsReadonlyNode:
            self._createServer()
        else:
            self._ready = True

    def _dbg_print_stats(self):
        print(Fore.CYAN + '[SIGN STATS] ──────────────────────────────────────────')
        print(Fore.CYAN + f'  SEND  total={self._dbg_send_total}  signed={self._dbg_send_signed}')
        print(Fore.CYAN + f'  RECV  total={self._dbg_recv_total}  verified={self._dbg_recv_verified}  dropped={self._dbg_recv_dropped}')
        print(Fore.CYAN + '────────────────────────────────────────────────────────')

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
        self._server = TcpServer(self._syncObj._poller, host, port,
                                 onNewConnection=self._onNewIncomingConnection,
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
        conn.setOnMessageReceivedCallback(functools.partial(self._onIncomingMessageReceived, conn))
        conn.setOnDisconnectedCallback(functools.partial(self._onDisconnected, conn))

    def _onIncomingMessageReceived(self, conn, message):
        if isinstance(message, list) and self._onUtilityMessage(conn, message):
            return

        if isinstance(message, dict) and message.get('type') == 'handshake':
            peer_node_name  = message.get('node_name')
            peer_cert       = message.get('certificate')
            peer_address    = message.get('address')
            cluster         = message.get('cluster', [])

            if peer_cert and peer_node_name:
                signature       = message.get('signature')
                signing_key_pem = message.get('signing_public_key')
                peer_public_key = self.signer.load_public_key_from_pem(signing_key_pem)
                # Must match exactly what _sendSelfAddress builds with sign_raw
                signed_message  = (','.join(cluster) + '||').encode() + peer_cert.encode()
                if not self.signer.validate(peer_public_key, signed_message, signature):
                    print(Fore.RED + f'Error: {peer_node_name} Failed Authentication!')
                    conn.disconnect()
                    return
                print(Fore.GREEN + f'Success: {peer_node_name} Authenticated!')
                self._peerSigningKeys[peer_address] = peer_public_key

            if peer_cert and peer_node_name:
                try:
                    with open(f'{peer_node_name}_certificate.pem', 'w') as f:
                        f.write(peer_cert)
                    print(Fore.YELLOW + f"[INCOMING] Received and saved certificate from {peer_node_name}")
                    if self._syncObj.encryptor:
                        self._syncObj.encryptor._load_certificates()
                except Exception as e:
                    print(Fore.YELLOW + f"[INCOMING] Failed to save certificate from {peer_node_name}: {e}")

            self._sendSelfAddress(conn)
            message = peer_address

        node = self._nodeAddrToNode[message] if message in self._nodeAddrToNode else None

        if node is None and message != 'readonly':
            print(Fore.RED + f'[HANDSHAKE] Unknown node address: {repr(message)}')
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

        if self._syncObj.encryptor:
            conn.encryptor = self._syncObj.encryptor

        conn.setOnMessageReceivedCallback(functools.partial(self._onVerifiedMessageReceived, node))

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
        return isinstance(node, TCPNode) and node not in self._preventConnectNodes and (
            self._selfIsReadonlyNode or self._selfNode.address > node.address)

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

    def _sendSelfAddress(self, conn):
        """Send handshake unencrypted — conn.encryptor must be None when called."""
        node_name = getattr(self._syncObj.conf, 'node_name', None)
        our_cert  = None
        signing_public_key = None

        try:
            with open('signing_public_key.pem', 'r') as file:
                signing_public_key = file.read()
        except FileNotFoundError:
            signing_public_key = None

        try:
            cert_file = f'{node_name}_certificate.pem' if node_name else 'certificate.pem'
            with open(cert_file, 'r') as f:
                our_cert = f.read()
        except FileNotFoundError:
            print(Fore.YELLOW + f"Warning: Certificate file not found for {node_name}")

        # Build the exact byte sequence the verifier will reconstruct, sign it raw
        cluster        = sorted([self._selfNode.address] + [n.address for n in self._nodes])
        signed_message = (','.join(cluster) + '||').encode() + our_cert.encode()
        signature      = self.signer.sign_raw(signed_message)

        addr = 'readonly' if self._selfIsReadonlyNode else self._selfNode.address
        conn.send({'type': 'handshake', 'node_name': node_name, 'address': addr,
                   'certificate': our_cert, 'signature': signature,
                   'signing_public_key': signing_public_key,
                   'cluster': cluster})

    def _onOutgoingConnected(self, conn):
        conn.setOnMessageReceivedCallback(functools.partial(self._onOutgoingHandshakeResponse, conn))
        self._sendSelfAddress(conn)

    def _onOutgoingHandshakeResponse(self, conn, message):
        if isinstance(message, dict) and message.get('type') == 'handshake':
            peer_node_name  = message.get('node_name')
            peer_cert       = message.get('certificate')
            peer_address    = message.get('address')
            signature       = message.get('signature')
            cluster         = message.get('cluster', [])

            if peer_cert and peer_node_name and signature:
                signing_key_pem = message.get('signing_public_key')
                peer_public_key = self.signer.load_public_key_from_pem(signing_key_pem)
                # Must match exactly what _sendSelfAddress builds with sign_raw
                signed_message  = (','.join(cluster) + '||').encode() + peer_cert.encode()
                if not self.signer.validate(peer_public_key, signed_message, signature):
                    print(Fore.RED + f'Error: {peer_node_name} digital signature rejected!')
                    conn.disconnect()
                    return
                print(Fore.GREEN + f'Success: {peer_node_name} Digital Signature Authenticated!')
                self._peerSigningKeys[peer_address] = peer_public_key

                try:
                    with open(f'{peer_node_name}_certificate.pem', 'w') as f:
                        f.write(peer_cert)
                    print(Fore.YELLOW + f"[OUTGOING] Received and saved certificate from {peer_node_name}")
                    if self._syncObj.encryptor:
                        self._syncObj.encryptor._load_certificates()
                except Exception as e:
                    print(Fore.YELLOW + f"[OUTGOING] Failed to save certificate from {peer_node_name}: {e}")
            else:
                print(Fore.YELLOW + "[OUTGOING] Handshake missing certificate or node_name")

        if self._syncObj.encryptor:
            conn.encryptor = self._syncObj.encryptor

        node = self._connToNode(conn)
        conn.setOnMessageReceivedCallback(functools.partial(self._onVerifiedMessageReceived, node))
        self._onNodeConnected(node)

    def _onVerifiedMessageReceived(self, node, message):
        self._dbg_recv_total += 1

        if not isinstance(message, bytes):
            print(Fore.RED + f'[VERIFY] Unexpected non-bytes type={type(message).__name__} — dropping!')
            self._dbg_recv_dropped += 1
            return

        node_addr       = getattr(node, 'address', None)
        peer_public_key = self._peerSigningKeys.get(node_addr)

        result = _unwrap_and_verify(self.signer, peer_public_key, message)
        if result is None:
            self._dbg_recv_dropped += 1
            return

        self._dbg_recv_verified += 1

        if self._dbg_recv_total % 50 == 0:
            self._dbg_print_stats()

        self._onMessageReceived(node, result)

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
        node_addr = getattr(node, 'address', None)
        if node_addr and node_addr in self._peerSigningKeys:
            del self._peerSigningKeys[node_addr]

    def send(self, node, message):
        if node not in self._connections or self._connections[node].state != CONNECTION_STATE.CONNECTED:
            return False
        if self._send_random_sleep_duration:
            time.sleep(random.random() * self._send_random_sleep_duration)

        if isinstance(message, dict) and message.get('type') == 'handshake':
            self._connections[node].send(message)
            return self._connections[node].state == CONNECTION_STATE.CONNECTED

        self._dbg_send_total += 1
        try:
            recipient_ips  = [n.address for n in self._nodes]
            signed_message = _wrap_and_sign(
                self.signer,
                message,
                self._selfNode.address,
                recipient_ips,
            )
            self._dbg_send_signed += 1
        except Exception as e:
            print(Fore.RED + f'[SIGN] Error signing message: {e}')
            signed_message = message

        if self._dbg_send_total % 50 == 0:
            self._dbg_print_stats()

        self._connections[node].send(signed_message)
        return self._connections[node].state == CONNECTION_STATE.CONNECTED

    def destroy(self):
        print(Fore.CYAN + '[SIGN] destroy() — final stats:')
        self._dbg_print_stats()
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
