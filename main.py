from socket import *
from struct import *
from time import *

# part1
class pcap:
    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write((pack('@IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 0x0000ffff, link_type)))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time()).split('.'))
        length = len(data)
        self.pcap_file.write(pack('@IIII', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()

def get_mac_addr(macbytes):
        bits = 0
        for j in range(8):
            if bool(macbytes[0] & (2 ** j)):
                bits += 2 ** j
        mac = str(format(bits, '02x'))
        for i in range(len(macbytes) - 1):
            bits = 0
            for j in range(8):
                if macbytes[i + 1] & (2 ** j):
                    bits += 2 ** j
            mac += ":" + str(format(bits, '02x'))
        return mac

class Ethernet:
    def __init__(self, data):
        dest_mac, src_mac, etherType = unpack('! 6s 6s H', data[:14])
        self.dst_mac = get_mac_addr(dest_mac)
        self.src_mac = get_mac_addr(src_mac)
        self.etherType = htons(etherType)
        if self.etherType == 8:
            self.nextLayer = IPv4(data[14:])
        elif self.etherType == 1544:
            self.nextLayer = ARP(data[14:])

    def show(self):
        print("* Ethernet Frame:")
        print("\t- Destination:", self.dst_mac)
        print("\t- Source:", self.src_mac)
        print("\t- EtherType:", self.etherType)
        if self.etherType == 8 or self.etherType == 1544:
            self.nextLayer.show()

class ARP:
    def __init__(self, data):
        self.HType, self.PType, self.HLen, self.PLen, self.Oper, self.SHA, self.SPA, self.THA, self.TPA = unpack('! H H B B H 6s 4s 6s 4s', data[:28])
        self.SHA = get_mac_addr(self.SHA)
        self.SPA = inet_ntoa(self.SPA)
        self.THA = get_mac_addr(self.THA)
        self.TPA = inet_ntoa(self.TPA)
        self.dataBytes = data[28:]

    def show(self):
        print("\t* ARP Header:")
        print("\t\t- Hardware Type:", self.HType)
        print("\t\t- Protocol Type:", self.PType)
        print("\t\t- Hardware Address Length:", self.HLen)
        print("\t\t- Protocol Address Length:", self.PLen)
        print("\t\t- Operation:", self.Oper)
        print("\t\t- Sender Hardware Address:", self.SHA)
        print("\t\t- Sender Protocol Address:", self.SPA)
        print("\t\t- Target Hardware Address:", self.THA)
        print("\t\t- Target Protocol Address:", self.TPA)
        print("\t\t- ARP Data:\n", self.dataBytes)

class IPv4:
    def __init__(self, data):
        self.header = unpack('!BBHHHBBH4s4s', data[:20])
        self.version = (self.header[0] >> 4)
        self.IHL = ((self.header[0] & 0xf) * 4)
        self.DSCP = (self.header[1] >> 2)
        self.ECN = (self.header[1] & 0x3)
        self.totalLength = self.header[2]
        self.identification = self.header[3]
        self.flagReserved = self.header[4] & 0x8000
        self.flagDF = self.header[4] & 0x4000
        self.flagMF = self.header[4] & 0x2000
        self.fragmentOffset = self.header[4] & 0x7fff
        self.ttl = self.header[5]
        self.protocol = self.header[6]
        self.checksum = self.header[7]
        self.ipchval = self.checksumVal(data[:self.IHL])
        self.srcIPAdd = inet_ntoa(self.header[8])
        self.dstIPAdd = inet_ntoa(self.header[9])
        if self.protocol == 1:
            self.nextLayer = ICMP(data[self.IHL:])
        elif self.protocol == 6:
            pseudoHeader = pack('!4s4sHH',
                                inet_aton(self.srcIPAdd),
                                inet_aton(self.dstIPAdd),
                                0x0006, self.totalLength - self.IHL)
            dataPacket = pseudoHeader + data[self.IHL:]
            tcpchval = self.checksumVal(dataPacket)
            self.nextLayer = TCP(data[self.IHL:], tcpchval)
        elif self.protocol == 17:
            self.nextLayer = UDP(data[self.IHL:])

    def checksumVal(self, data):
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + (data[i + 1])
            elif i + 1 == len(data):
                s += (data[i])
            else:
                print("what the fuck!?", i, len(data))
        s += (s >> 16)
        s = s & 0xffff
        if s == 65535:
            return True
        else:
            return False

    def show(self):
        print("\t* IPv4 Packet: ")
        print("\t\t- Version:", self.version)
        print("\t\t- Internet Header Length:", self.IHL)
        print("\t\t- Differentiated Services Code Point:", self.DSCP)
        print("\t\t- Explicit Congestion Notification:", self.ECN)
        print("\t\t- Total Length:", self.totalLength)
        print("\t\t- Identification:", self.identification)
        print("\t\t- Don't Fragment Flag:", self.flagDF)
        print("\t\t- More Fragments Flag:", self.flagMF)
        print("\t\t- Fragment Offset:", self.fragmentOffset)
        print("\t\t- Time to Live:", self.ttl)
        print("\t\t- Protocol:", self.protocol)
        print("\t\t- Header Checksum:", hex(self.checksum), ", Validity:", self.ipchval)
        print("\t\t- Source IP Address:", self.srcIPAdd)
        print("\t\t- Destination IP Address:", self.dstIPAdd)
        if self.protocol == 1 or self.protocol == 6 or self.protocol == 17:
            self.nextLayer.show()

class ICMP:
    def __init__(self, data):
        self.type, self.code, self.checksum = unpack('!BBH', data[:4])
        self.checksum = hex(self.checksum)
        self.binData = data[4:]

    def show(self):
        print("\t\t* ICMP Packet:")
        print("\t\t\t- ICMP Type:", self.type)
        print("\t\t\t- ICMP Code:", self.code)
        print("\t\t\t- ICMP Checksum:", self.checksum)
        print("\t\t\t- Data:\n", self.binData)

class TCP:
    def __init__(self, data, val):
        self.header = unpack("!HHLLBBHHH", data[:20])
        self.srcPort = self.header[0]
        self.dstPort = self.header[1]
        self.sqncNum = self.header[2]
        self.dataOfset = ((self.header[4] & 0xf0) >> 4)
        self.reserved = ((self.header[4] & 0xe) >> 1)
        self.ACK = bool(self.header[5] & 0x10)
        if self.ACK == 1:
            self.ackNum = self.header[3]
        self.NS = bool(self.header[4] & 0x1)
        self.CWR = bool(self.header[5] & 0x80)
        self.ECE = bool(self.header[5] & 0x40)
        self.URG = bool(self.header[5] & 0x20)
        self.PSH = bool(self.header[5] & 0x8)
        self.RST = bool(self.header[5] & 0x4)
        self.SYN = bool(self.header[5] & 0x2)
        self.FIN = bool(self.header[5] & 0x1)
        self.winSize = self.header[6]
        self.checksum = self.header[7]
        self.chval = val
        if self.URG == 1:
            self.urgPoint = self.header[8]
        if self.srcPort == 80 or self.dstPort == 80:
            self.appLayer = HTTP(data[20:])
        else:
            self.binData = data[20:]

    def show(self):
        print("\t\t* TCP Segment:")
        print("\t\t\t- Source Port:", self.srcPort)
        print("\t\t\t- Destination Port:", self.dstPort)
        print("\t\t\t- Sequence Number:", self.sqncNum)
        print("\t\t\t- Data Offset:", self.dataOfset)
        print("\t\t\t- Reserved: ", self.reserved)
        if self.ACK == 1:
            print("\t\t\t- Acknowledgment Number:", self.ackNum)
        print( "\t\t\t- Flags:")
        print("\t\t\t\t- NS:",self.NS, ", CWR:", self.CWR, ", ECE:", self.ECE)
        print("\t\t\t\t- URG:", self.URG, ", ACK:", self.ACK, ", PSH:", self.PSH)
        print("\t\t\t\t- RST:", self.RST, ", SYN:", self.SYN, ", FIN:", self.FIN)
        print("\t\t\t- Window Size:", self.winSize)
        print("\t\t\t- Checksum:", hex(self.checksum), ", Validity:", self.chval)
        if self.URG == 1:
            print("\t\t\t- Urgent Pointer:", self.urgPoint)
        if self.srcPort == 80 or self.dstPort == 80:
            self.appLayer.show()
        else:
            print("\t\t\t- TCP Data:\n", self.binData)

class UDP:
    def __init__(self, data):
        self.header = unpack('!HHHH', data[:8])
        self.srcPort = self.header[0]
        self.dstPort = self.header[1]
        self.len = self.header[2]
        self.checksum = self.header[3]
        if self.srcPort == 53 or self.dstPort == 53:
            self.appLayer = DNS(data[8:])
        else:
            self.binData = data[8:]

    def show(self):
        print("\t\t* UDP Segment:")
        print("\t\t\t- Source Port:", self.srcPort)
        print("\t\t\t- Destination Port:", self.dstPort)
        print("\t\t\t- Length:", self.len)
        print("\t\t\t- Checksum", hex(self.checksum))
        if self.srcPort == 53 or self.dstPort == 53:
            self.appLayer.show()
        else:
            print("\t\t\t- UDP Data:\n", self.binData)

class DNS:
    def __init__(self, data):
        self.header = unpack('!HBBHHHH', data[:12])
        self.ID = self.header[0]
        self.QR = bool(self.header[1] & 0x80)
        self.Opcode = ((self.header[1] & 0x78) >> 3)
        self.AA = bool(self.header[1] & 0x4)
        self.TC = bool(self.header[1] & 0x2)
        self.RD = bool(self.header[1] & 0x1)
        self.RA = bool(self.header[2] & 0x8)
        self.Z = (self.header[2] & 0x40)
        self.AD = (self.header[2] & 0x20)
        self.CD = (self.header[2] & 0x10)
        self.RCode = (self.header[2] & 0xf)
        self.QDCount = self.header[3]
        self.ANCount = self.header[4]
        self.NSCount = self.header[5]
        self.ARCount = self.header[6]
        self.binData = data[12:]

    def show(self):
        print("\t\t\t* DNS Massage:")
        print("\t\t\t\t- Transaction ID:", self.ID)
        print("\t\t\t\t- OpCode:", self.Opcode)
        print("\t\t\t\t- Flags:")
        print("\t\t\t\t\t- QR:", self.QR, ", AA:", self.AA, ", TC:", self.TC)
        print("\t\t\t\t\t- RD:", self.RD, ", RA:", self.RA)
        print("\t\t\t\t\t- Z:", self.Z, ", AD:", self.AD, ", CD:", self.CD)
        print("\t\t\t\t- RCode:", self.RCode)
        print("\t\t\t\t- Number of Questions:", self.QDCount)
        print("\t\t\t\t- Number of Answer RRs:", self.ANCount)
        print("\t\t\t\t- Number of Authority RRs:", self.NSCount)
        print("\t\t\t\t- Number of Additional RRs:", self.ARCount)
        print("\t\t\t\t- DNS Data:\n", self.binData)

class HTTP:
    def __init__(self, data):
        self.msg = data

    def show(self):
        print("\t\t\t* HTTP Massage:")
        print(self.msg)

#part2
class scanPacket:
    def __init__(self, srcAdd, dstAdd, srcPort, dstPort, scanType):
        #     IP Header
        srcAdd = inet_aton(srcAdd)
        dstAdd = inet_aton(dstAdd)
        self.ip_Header = pack('!BBHHHBBH4s4s',
                              0x45, 0x00, 0x0028,
                              0xffff, 0x0000,
                              0xff, 0x06, 0x0000,
                              srcAdd,
                              dstAdd)
        chksm = self.checksum(self.ip_Header)
        self.ip_Header = pack('!BBHHHBBH4s4s',
                              0x45, 0x00, 0x0028,
                              0xffff, 0x0000,
                              0xff, 0x06, chksm,
                              srcAdd,
                              dstAdd)
        #     TCP Header
        if scanType == 0:    # ACK scan or Window scan
            flags = 0x10
        elif scanType == 1:  # SYN scan
            flags = 0x02
        elif scanType == 2:  # FIN scan
            flags = 0x01
        self.tcp_header = pack('!HHLLBBHHH',
                               srcPort, dstPort,
                               0xf0f0f0f0,
                               0x0f0f0f0f,
                               0x50, flags, 0x0400,
                               0x0000, 0x0000)
        pseudoHeader = pack('!4s4sHH',
                            srcAdd,
                            dstAdd,
                            0x0006, 0x0014)
        dataPacket = pseudoHeader + self.tcp_header
        chksm = self.checksum(dataPacket)
        self.tcp_header = pack('!HHLLBBHHH',
                               srcPort, dstPort,
                               0xf0f0f0f0,
                               0x0f0f0f0f,
                               0x50, flags, 0x0400,
                               chksm, 0x0000)
        self.packet = self.ip_Header + self.tcp_header

    def show(self):
        tmp = IPv4(self.packet)
        tmp.show()
        print()

    def checksum(self, dataBytes):
        cs = 0
        for i in range(0, len(dataBytes), 2):
            cs += ((dataBytes[i] << 8) + dataBytes[i + 1])
        cs += (cs >> 16)
        cs = ~cs
        cs = cs & 0xffff
        return cs
