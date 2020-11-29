import argparse
from main import *
from threading import Thread
from services import services

s = socket(AF_INET, SOCK_STREAM)
s.connect(('216.58.110.68', 80))
myIP = s.getsockname()[0]
s.close()

scan_ports = set()


def connect_scan(ip, sp, fp, d):
    for i in range(sp, fp + 1):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(d)
        try:
            s.connect((ip, i))
            if str(i) in services:
                print("\t-> Port", i, "is OPEN,\tService:", services[str(i)])
            else:
                print("\t-> Port", i, "is OPEN,\tNo Services Found!")
            s.close()
        except:
            if str(i) in services:
                print("\t-> Port", i, "is CLOSE,\tService:", services[str(i)])
            else:
                print("\t-> Port", i, "is CLOSE,\tNo Services Found!")
            s.close()
    print("\n\t\t* End of Scan!\n\n")


def sendPackets(ip, sp, fp, d, type):
    send = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
    send.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    for i in range(sp, fp + 1):
        spct = scanPacket(myIP, ip, 9999, i, type)
        send.sendto(spct.packet, (ip, 0))
        sleep(d)


def ACK_scan_rec(ip, sp, fp, d):
    global scan_ports
    sTime = time()
    tTime = d * (fp - sp + 1)
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    while (time() - sTime) <= tTime:
        raw_data, addr = conn.recvfrom(65535)
        tmp = Ethernet(raw_data)
        if tmp.etherType == 8:
            if tmp.nextLayer.srcIPAdd == ip and tmp.nextLayer.dstIPAdd == myIP:
                port = tmp.nextLayer.nextLayer.srcPort
                if sp <= port <= fp:
                    if tmp.nextLayer.protocol == 6:
                        if tmp.nextLayer.nextLayer.RST == 1:
                            if port not in scan_ports:
                                scan_ports.add(port)
                                if str(port) in services:
                                    print("\t-> Port", port, "is UNFILTERED,\tService:", services[str(port)])
                                else:
                                    print("\t-> Port", port, "is UNFILTERED,\tNo Services Found!")
                    elif tmp.nextLayer.protocol == 1:
                        if tmp.nextLayer.nextLayer.type == 3:
                            if tmp.nextLayer.nextLayer.code in [1, 2, 3, 9, 10, 13]:
                                if port not in scan_ports:
                                    scan_ports.add(port)
                                    if str(port) in services:
                                        print("\t-> Port", port, "is FILTERED,\tService:", services[str(port)])
                                    else:
                                        print("\t-> Port", port, "is FILTERED,\tNo Services Found!")
    for i in range(sp, fp + 1):
        if i not in scan_ports:
            if str(i) in services:
                print("\t-> Port", i, "is FILTERED,\tService:", services[str(i)])
            else:
                print("\t-> Port", i, "is FILTERED,\tNo Services Found!")
    print("\n\t\t* End of Scan!\n\n")


def SYN_scan_rec(ip, sp, fp, d):
    global scan_ports
    sTime = time()
    tTime = d * (fp - sp + 1)
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    while (time() - sTime) <= tTime:
        raw_data, addr = conn.recvfrom(65535)
        tmp = Ethernet(raw_data)
        if tmp.etherType == 8:
            if tmp.nextLayer.srcIPAdd == ip and tmp.nextLayer.dstIPAdd == myIP:
                port = tmp.nextLayer.nextLayer.srcPort
                if tmp.nextLayer.protocol == 6 and sp <= port <= fp:
                    if tmp.nextLayer.nextLayer.SYN == 1 and tmp.nextLayer.nextLayer.ACK == 1:
                        if port not in scan_ports:
                            scan_ports.add(port)
                            if str(port) in services:
                                print("\t-> Port", port, "is OPEN,\tService:", services[str(port)])
                            else:
                                print("\t-> Port", port, "is OPEN,\tNo Services Found!")
                    elif tmp.nextLayer.nextLayer.RST == 1:
                        if port not in scan_ports:
                            scan_ports.add(port)
                            if str(port) in services:
                                print("\t-> Port", port, "is CLOSE,\tService:", services[str(port)])
                            else:
                                print("\t-> Port", port, "is CLOSE,\tNo Services Found!")
    for i in range(sp, fp + 1):
        if i not in scan_ports:
            if str(i) in services:
                print("\t-> Port", i, "is CLOSE,\tService:", services[str(i)])
            else:
                print("\t-> Port", i, "is CLOSE,\tNo Services Found!")
    print("\n\t\t* End of Scan!\n\n")


def FIN_scan_rec(ip, sp, fp, d):
    sTime = time()
    tTime = d * (fp - sp + 1)
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    while (time() - sTime) <= tTime:
        raw_data, addr = conn.recvfrom(65535)
        tmp = Ethernet(raw_data)
        if tmp.etherType == 8:
            if tmp.nextLayer.srcIPAdd == ip and tmp.nextLayer.dstIPAdd == myIP:
                port = tmp.nextLayer.nextLayer.srcPort
                if sp <= port <= fp:
                    if tmp.nextLayer.protocol == 6:
                        if tmp.nextLayer.nextLayer.RST == 1:
                            if port not in scan_ports:
                                scan_ports.add(port)
                                if str(port) in services:
                                    print("\t-> Port", port, "is CLOSE,\tService:", services[str(port)])
                                else:
                                    print("\t-> Port", port, "is CLOSE,\tNo Services Found!")
                    elif tmp.nextLayer.protocol == 1:
                        if tmp.nextLayer.nextLayer.type == 3:
                            if tmp.nextLayer.nextLayer.code in [1, 2, 3, 9, 10, 13]:
                                if port not in scan_ports:
                                    scan_ports.add(port)
                                    if str(port) in services:
                                        print("\t-> Port", port, "is FILTERED,\tService:", services[str(port)])
                                    else:
                                        print("\t-> Port", port, "is FILTERED,\tNo Services Found!")
    for i in range(sp, fp + 1):
        if i not in scan_ports:
            if str(i) in services:
                print("\t-> Port", i, "is OPEN or FILTERED or not RFC793,\tService:", services[str(i)])
            else:
                print("\t-> Port", i, "is OPEN or FILTERED or not RFC793,\tNo Services Found!")
    print("\n\t\t* End of Scan!\n\n")


def WIN_scan_rec(ip, sp, fp, d, ):
    sTime = time()
    global scan_ports
    tTime = d * (fp - sp + 1)
    conn = socket(AF_PACKET, SOCK_RAW, ntohs(3))
    while (time() - sTime) <= tTime:
        if len(scan_ports) == (fp - sp + 1):
            break
        raw_data, addr = conn.recvfrom(65535)
        tmp = Ethernet(raw_data)
        if tmp.etherType == 8:
            if tmp.nextLayer.srcIPAdd == ip and tmp.nextLayer.dstIPAdd == myIP:
                port = tmp.nextLayer.nextLayer.srcPort
                if sp <= port <= fp:
                    if tmp.nextLayer.protocol == 6:
                        if tmp.nextLayer.nextLayer.RST == 1:
                            if port not in scan_ports:
                                scan_ports.add(port)
                                if tmp.nextLayer.nextLayer.winSize == 0:
                                    if str(port) in services:
                                        print("\t-> Port", port, "is CLOSE,\tService:", services[str(port)])
                                    else:
                                        print("\t-> Port", port, "is CLOSE,\tNo Services Found!")
                                else:
                                    if str(port) in services:
                                        print("\t-> Port", port, "is OPEN,\tService:", services[str(port)])
                                    else:
                                        print("\t-> Port", port, "is OPEN,\tNo Services Found!")
                    elif tmp.nextLayer.protocol == 1:
                        if tmp.nextLayer.nextLayer.type == 3:
                            if tmp.nextLayer.nextLayer.code in [1, 2, 3, 9, 10, 13]:
                                if port in scan_ports:
                                    scan_ports.add(port)
                                    if str(port) not in services:
                                        print("\t-> Port", port, "is FILTERED,\tService:", services[str(port)])
                                    else:
                                        print("\t-> Port", port, "is FILTERED,\tNo Services Found!")
    for i in range(sp, fp + 1):
        if i not in scan_ports:
            if str(i) in services:
                print("\t-> Port", i, "is FILTERED,\tService:", services[str(i)])
            else:
                print("\t-> Port", i, "is FILTERED,\tNo Services Found!")
    print("\n\t\t* End of Scan!\n\n")


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", required=True, default=None, type=str, help="Input Your Scan Target. as: 176.101.52.155")
parser.add_argument("-p", "--port", required=True, default=None, type=str, help="Input Your Scan Ports. as: 10-100")
parser.add_argument("-s", "--scan", required=True, default=None, type=str, help="Input Your Scan Type. CS(Connect Scan), AS(ACK Scan), SS(SYN Scan), FS(FIN Scan), WS(Window Scan)")
parser.add_argument("-d", "--delay", required=False, default=2, type=int, help="Input Your Scan Delay. as: 3 decisecond")
args = parser.parse_args()
sPort = args.port.split('-')
fPort = int(sPort[1])
sPort = int(sPort[0])
tIP = gethostbyname(args.target)
delay = args.delay / 10

if args.scan == "CS":
    print("\n Connect Scan On Target", tIP, ", from Port", sPort, "to", fPort, "with Delay", delay, "Second\n")
    connect_scan(tIP, sPort, fPort, delay)
elif args.scan == "AS":
    print("\n ACK Scan Target", tIP, ", from Port", sPort, "to", fPort, "with Delay", delay, "Second\n")
    Thread(target=ACK_scan_rec, args=(tIP, sPort, fPort, delay)).start()
    Thread(target=sendPackets, args=(tIP, sPort, fPort, delay, 0)).start()
elif args.scan == "SS":
    print("\n SYN Scan Target", tIP, ", from Port", sPort, "to", fPort, "with Delay", delay, "Second\n")
    Thread(target=SYN_scan_rec, args=(tIP, sPort, fPort, delay)).start()
    Thread(target=sendPackets, args=(tIP, sPort, fPort, delay, 1)).start()
elif args.scan == "FS":
    print("\n FIN Scan Target", tIP, ", from Port", sPort, "to", fPort, "with Delay", delay, "Second\n")
    Thread(target=FIN_scan_rec, args=(tIP, sPort, fPort, delay)).start()
    Thread(target=sendPackets, args=(tIP, sPort, fPort, delay, 2)).start()
elif args.scan == "WS":
    print("\n Window Scan Target", tIP, ", from Port", sPort, "to", fPort, "with Delay", delay, "Second\n")
    Thread(target=WIN_scan_rec, args=(tIP, sPort, fPort, delay)).start()
    Thread(target=sendPackets, args=(tIP, sPort, fPort, delay, 0)).start()


