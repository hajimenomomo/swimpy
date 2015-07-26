"""
A SWIM Failure Detector Implementation by Mohamed Messaad
"""

#Python Imports
import argparse, time, uuid, socket, struct
from random import shuffle
#Twisted Imports
from twisted.internet import reactor, protocol, defer
from twisted.python import log


def format_address(host, port):

    def check_address(addr):
        try:
            socket.inet_aton(addr)
            return addr
        except socket.error:
            return '127.0.0.1'

    if host and port:
        return ("%s:%d") % (check_address(host), port)

def parse_args():
    parser = argparse.argumentParser()
    parser.add_argument("-p", help="server listening port (UDP)", type=int)
    parser.add_argument("addr", help="remote address")
    args = parser.parse_args()

    def parse_address(addr):
        if ':' not in addr:
            host = '127.0.0.1'
            port = addr
        else:
            host, port = addr.split(':', 1)
        return host, int(port)

    return args


class Host(object):

    def __init__(self, process_id, addr='127.0.0.1', port=8000):
        self.processId = process_id
        self.addr = addr
        self.port = port

    def serialize(self):
        return struct.pack("!16s4sh", self.processId.bytes,
                            socket.inet_aton(self.addr), self.port)

    def deserialize(self, data):
        unpackTuple = struct.unpack("!16s4sh", data)
        proc_id, addr, self.port = unpackTuple
        self.processId = uuid.UUID(bytes=proc_id)
        self.addr = socket.inet_ntoa(addr)


class MemberStorage(object):
    members = []

    @property
    def serialized(self):
        result = ''
        for host in self.members:
            result += host.serialize()
        return result

    def host_alive(self, host):
        if host not in self.members:
            self.members.append(host)

    def remove_host(self, host):
        if host in self.members:
            self.members.remove(host)

    def shuffle_hosts(self):
        shuffle(self.members)

    def show_hosts(self):
        return str(self.members)

"""
class SWIMProcess(object):
    _members = []
    processId = uuid.uuid1()

    def __init__(self, port):
        self.port = port

    def run(self):
        reactor.listenUDP(self.port, SWIMProtocol())
        print "server listening on port %d" % self.port
        reactor.run()
"""

class SWIMProtocol(protocol.DatagramProtocol):
    #Protocol parameters
    T_ROUND = 1
    K_SUBGROUP_SIZE = 4

    #SWIM Protocol Header
    SWIM_PROTO = "\xDE\xED"

    #SWIM Protocol message types
    PING = "\x00"
    ACK = "\x01"
    PING_REQ = "\x03"
    JOIN = "\x04"
    LEAVE = "\x05"

    #Notification header, appended after message type
    NOTIF = "\xF0\x0D"

    #Data structures, hosts, notifications

    membership_list = MemberStorage()
    notifications = []

    def datagramReceived(self   , data, (host, port)):

        if data[:2] != self.SWIM_PROTO: #Check if SWIM message
            return
        data = data[2:]
        print "SWIM Packet received"

        header, data = data[:1], data[1:]

        if header == self.PING:
            pass
        elif header == self.ACK:
            pass
        elif header == self.PING_REQ:
            pass
        elif header == self.JOIN:
            pass
        elif header == self.LEAVE:
            pass
        else:
            return

    def stopProtocol(self):
        #Notify other nodes with a LEAVE message
        pass

    def startProtocol(self, host):
        pass

    def join(host):
        pass

    def ping(self, (host,port)):
        ping_message = self.SWIM_PROTO + self.PING
        ping_deferred = defer.Deferred()
        return ping_deferred

    def ack(self, (host, port)):
        ack_message = self.SWIM_PROTO + self.ACK

    def pingReq(self, host):
        pass

    def handleAck(self, data, (host, port)):
        pass

    def handleJoin(self, host):
        pass

    def handlePing(self, data, (host, port)):
        pass

    def handlePingReq(self, data, (host, port)):
        pass

    def makeNotif(type, host):
        pass




class JoinServer(protocol.Protocol):
    """
    This class is used to transfer the membership list over TCP
    after a peer joins
    """
    def __init__(self, membership):
        self.membership = membership_list

    def connectionMade(self):
        self.transport.write(self.swimprotocol.membership_list.serialized)
        self.transport.loseConnection()

class JoinServerFactory(protocol.Protocol):
    """
    Factory class for the Join Server
    """
    protocol = JoinServer


class JoinClient(protocol.Protocol):
    def connectionMade(self):
        pass
    def connectionLost(self, reason):
        pass

class JoinClientFactory(protocol.ClientFactory):
    protocol = joinClient



if __name__ == '__main__':
    #Parser Initialization
    reactor.listenUDP(8200, SWIMProtocol())
    reactor.run()
