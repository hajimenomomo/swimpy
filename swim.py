"""
A SWIM Failure Detector Implementation by Mohamed Messaad
"""

#Python Imports
import argparse, time, uuid, socket, struct
from random import shuffle
from heapq import nlargest
#Twisted Imports
from twisted.internet import reactor, protocol, defer
from twisted.python import log

def format_address(host, port):
    if host and port:
        return ("%s:%d") % (check_address(host), port)

def check_address(addr):
        try:
            socket.inet_aton(addr)
            return addr
        except socket.error:
            return '127.0.0.1'

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

class Notification:
    """
    This class represents a notification to forward to other peers in the network
    """

    NOTIF_TYPES = dict(JOIN="\xF0", LEAVE = "\xF1", DOWN = "\xF2") #Possibility of adding new notification types

    def __init__(self, type="\xF0", host=None):
        if type not in self.NOTIF_TYPES.values():  #Control the input of type
            type = self.NOTIF_TYPES['JOIN']
        self.type = type
        self.host = host

    @property
    def serialized(self):
        return struct.pack("!1s22s", self.type, self.host.serialized)

    def deserialize(self, data):
        type, host_data = struct.unpack("!1s22s", data)
        self.type = type
        self.host = Host()
        self.host.deserialize(host_data)

    def __repr__(self):
        for k,v in self.NOTIF_TYPES.items():
            if self.type == v:
                str_type = k
        return "%s, %s " % (str_type, str(self.host))

    def __eq__(self, other):
        return repr(other) == repr(self)



class NotificationStorage:
    """
    This class handles the storage and forwarding of status notifications
    """
    N_RETRANSMIT = 3
    LEN_NOTIF = len(Notification().serialized)
    PIGGYBACK_PER_MESSAGE = 8

    def __init__(self):
        self.notifications = []
        self.counters = []

    def __repr__(self):
        return str(self.notifications)

    def get_notification(self):
        for n in self.notifications:
            self.counters[self.notifications.index(n)] -=1

            if(self.counters[self.notifications.index(n)] == 0):
                del self.counters[self.notifications.index(n)]
                self.notifications.remove(n)


    def add_notification(self, notification):
        if notification in self.notifications:
            return
        self.notifications.append(notification)
        self.counters.append(self.N_RETRANSMIT)

    @property
    def serialized(self):
        result = ''
        for n in self.notifications:
            result += n.serialized
        return result

    def deserialize(self, data):
        if len(data) % self.LEN_NOTIF != 0:
            return
        while (len(data)!=0):
            buffer, data = data[:self.LEN_NOTIF], data[self.LEN_NOTIF:]
            notif = Notification()
            notif.deserialize(buffer)
            self.add_notification(notif)

    def notifications_to_piggyback(self):
        """
        This method returns the least piggybacked notifications in a network serialized form
        """
        indexes_to_piggyback = nlargest(4, range(len(self.counters)), key=self.counters.__getitem__)
        res = ''
        for i in indexes_to_piggyback:
            res += self.notifications[i].serialized
            self.counters[i] -=1
            if self.counters[i] == 0:
                del self.counters[i]
                del self.notifications[i]

        return res







class Host(object):
    """
    This class represents a member of the membership network
    """

    def __init__(self, process_id = uuid.uuid1(), addr='127.0.0.1', port=8000): # Pad processId for serialization
        self.processId = process_id
        self.addr = check_address(addr)
        self.port = port

    @property
    def serialized(self):
        return struct.pack("!16s4sh", self.processId.bytes,
                            socket.inet_aton(self.addr), self.port)

    def deserialize(self, data):
        unpackTuple = struct.unpack("!16s4sh", data)
        proc_id, addr, self.port = unpackTuple
        self.processId = uuid.UUID(bytes=proc_id)
        self.addr = socket.inet_ntoa(addr)

    def __repr__(self):
        return "PID: %s addr: %s port: %d" % (str(self.processId), self.addr, self.port)

    def __hash__(self):
        return hash(repr(self))

    def __eq__(self, other):
        return repr(other) == repr(self)

    def __ne__(self, other):
        return not self.__eq__(other)

class MemberStorage(object):
    """
    This class implements a membership storage
    """
    LEN_HOST = len(Host().serialized)

    def __init__(self):
        self.members = []

    @property
    def serialized(self):
        result = ''
        for host in self.members:
            result += host.serialized
        return result

    def deserialize(self, data):
        if len(data) % self.LEN_HOST != 0:
            return
        while (len(data)!=0):
            buffer, data = data[:self.LEN_HOST], data[self.LEN_HOST:]
            host = Host()
            host.deserialize(buffer)
            self.host_alive(host)



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
    PING_TIMEOUT = 0.5
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

    def datagramReceived(self, data, (host, port)):

        if data[:2] != self.SWIM_PROTO: #Check if SWIM message
            return
        data = data[2:]
        print "SWIM Packet received"

        header, data = data[:1], data[1:]

        if header == self.PING:
            self.ack(host, port)
        elif header == self.ACK:
            pass
        elif header == self.PING_REQ:
            self.ping(host, port)
        elif header == self.JOIN:

            pass
        elif header == self.LEAVE:
            pass
        else:
            pass


    def stopProtocol(self):
        #Notify other nodes with a LEAVE message
        pass

    def startProtocol(self, host):
        pass

    def join(host):
        pass

    def ping(self, host, port, timeout=PING_TIMEOUT):
        ping_message = self.SWIM_PROTO + self.PING
        ping_deferred = defer.Deferred()
        self.transport.write(ping_message, (host,port))
        return ping_deferred

    def ack(self, host, port):
        ack_message = self.SWIM_PROTO + self.ACK
        self.transport.write(ack_message, (host,port))

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

    def join(self, host, port):
        join_message = self.SWIM_PROTO+self.JOIN
        self.transport.write(join_message, (host,port))

    def ping_timeout(self):

        return



# The next two classes are used to transfer raliably the membership list during the Join procedure

class JoinServerProtocol(protocol.Protocol):
    """
    This class is used to transfer the membership list over TCP
    after a peer joins
    """

    def connectionMade(self):
        self.transport.write(self.factory.membership.serialized)
        self.transport.loseConnection()

    def connectionLost(self, reason):
        print 'transfer finished'



class JoinServerFactory(protocol.Factory):
    """
    Factory class for the Join Server
    """
    protocol = JoinServerProtocol

    def __init__(self, membership):
        self.membership = membership



def get_membership(host, port):
    """
    Download a membership list from the given host and port. This function
    returns a Deferred which will be fired with the complete list or a Failure
     if the membership could not be downloaded.
    """
    d = defer.Deferred()
    factory = JoinClientFactory(d)
    d.addCallbacks(got_membership,transfer_failed)
    reactor.connectTCP(host, port, factory)
    return d

def got_membership(data):
    m = MemberStorage()
    m.deserialize(data)
    print m.show_hosts()
    print len(m.serialized)
    return m

def transfer_failed(failure):
    print 'Failed Join Membership Transfer'


def serve_membership():
    m = MemberStorage()
    m.host_alive(Host(port=8153))
    m.host_alive(Host(port=8128))
    m.host_alive(Host(addr='8.8.8.8'))
    print m.show_hosts()
    factory = JoinServerFactory(m)
    reactor.listenTCP(8200, factory)
    reactor.run()



class JoinClientProtocol(protocol.Protocol):
    membership = ''
    def dataReceived(self, data):
        self.membership += data
        print len(data)

    def connectionLost(self, reason):
        self.factory.transfer_finished(self.membership)


class JoinClientFactory(protocol.ClientFactory):
    protocol = JoinClientProtocol

    def __init__(self, deferred):
        self.deferred = deferred

    def transfer_finished(self, membership):
        print 'factory transfer finished'
        if self.deferred is not None:
            d, self.deferred = self.deferred, None
            d.callback(membership)

    def clientConnectionFailed(self, connector, reason):
        print 'client connection failed'
        if self.deferred is not None:
            d, self.deferred = self.deferred, None
            d.errback(reason)



if __name__ == '__main__':
    #Parser Initialization
    pass
