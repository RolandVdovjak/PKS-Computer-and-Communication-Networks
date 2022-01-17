from scapy.all import *
import binascii
import sys
from os import listdir
from os.path import isfile, join
import os

f_path = ".\\Pcap\\"    # Cesta ku testovacim
files = []      # Testovacie subory
frames = []     # Raw ramce

    # Frame type
ETH_p = ""
IEEE_p = ""

    # Polia pre nacitanie protokolov z externych suborov
ETHprot = [],[]
IEEEprot = [],[]
IPprot = [],[]
PORTprot = [],[]
ICMPprot = [],[]

    # Pole pre ulohu 3
IP_list = [],[]

    # Polia pre ulohu 4
HTTP_l = [[]]
HTTPS_l = [[]]
TELNET_l = [[]]
SSH_l = [[]]
FTP_CONTROL_l = [[]]
FTP_DATA_l = [[]]
TFTP_l = [[]]
ICMP_l = [[]]
ARP_l = [[]]

    # Objekt Ramca
class FRAME:
    def __init__(self, order, len_api, len_real, d_mac, s_mac, d_ip, s_ip, prot,  hexgulas, flag = None, d_port = None, s_port = None ):
        self.order = order
        self.len_api = len_api
        self.len_real = len_real
        self.d_mac = d_mac
        self.s_mac = s_mac
        self.d_ip = d_ip
        self.s_ip = s_ip
        self.prot = prot
        self.hexagulas = hexgulas
        self.flag = flag
        self.d_port = d_port
        self.s_port = s_port

    # ZISTENIE REALNEJ DLZKY RAMCA
def real_len(frame):
    if len(frame) < 60:
        l = 64
    else:
        l = len(frame)+4
    return l

    # VYLEPSENIE TVARU MAC ADRESY
def mac_out(mac):
    mac_f= ""
    for i in range (0,6):
        mac_f = mac_f + mac[i*2:i*2+2] + ':'
    return mac_f[:-1]

    # URCOVANIE TYPU RAMCA (Protokol na 2 vrstve)
def frame_type(frame):
    f_type = ""
    global IEEE_p

    if int(frame[24:28], 16) >= 1536:
            # ETH
        f_type = "Ethernet II"
        find_ETH_p(frame[24:28]) # Zistovanie Protokolu 3. vrstvy
    else:
            #IEEE
        if str(frame[28:32]) == "ffff":
            f_type = "IEEE 802.3 - raw"
            IEEE_p = "IPX"

        elif str(frame[28:32]) == "aaaa":
            f_type = "IEEE 802.3 LLC & SNAP"

                # Zistovanie Protokolu 3. vrstvy
            find_IEEE_p(frame[32:34])
            find_ETH_p(frame[40:44])

        else:
            f_type = "IEEE 802.3 LLC"
            find_IEEE_p(frame[32:34]) # Zistovanie Protokolu 3. vrstvy

    return f_type

    # NACITANIE PROTOKOLOV Z EXTERNZCH SUBOROV
def loadProt(prot):
        # Pocet znakov pre '$'
    if prot == "IEEE" or prot == "ICMP":
        n = 2
    else:
        n = 4

    p_file = open(".\\Prot\\" + prot + "_prot.txt", 'r')

    with open(p_file.name) as f :
        lines = f.readlines()
    global ETHprot

    list = eval(prot + "prot")

    for line in lines:
        list[0].append(line[:n])
        list[1].append(line[n + 1:-1])

    # ZISTENIE ETHERNET PROTOKOLU
def find_ETH_p(h):
    p = ""
    i = 0

    while p == "" and i < len(ETHprot[0]):
        if ETHprot[0][i] == h:
            p = ETHprot[1][i]
        i += 1
    global ETH_p
    ETH_p = p

    # ZISTENIE IEEE PROTOKOLU
def find_IEEE_p(h):
    p = ""
    i = 0

    while p == "" and i < len(IEEEprot[0]):
        if IEEEprot[0][i] == h:
            p = IEEEprot[1][i]
        i += 1
    global IEEE_p
    IEEE_p = p

    # ZISTENIE PORTOVEHO PROTOKOLU
def find_PORT(val):
    p = ""
    i = 0

    while p == "" and i < len(PORTprot[0]):
        if int(PORTprot[0][i]) == val:
            p = PORTprot[1][i]
        i += 1
    return p

    # VYLEPSENIE TVARU IP ADRESY
def ip_out(ip):
    ip_f = ""
    for i in range(0,4):
        ip_f = ip_f + str(int(ip[i*2:i*2 + 2], 16)) + "."

    return ip_f[:-1]

    # ZISTENIE IP PROTOKOLU
def find_ip_prot(val):
    p = ""
    i = 0
    while p == "" and i < len(IPprot[0]):
        if int(IPprot[0][i]) == int(val, 16):
            p = IPprot[1][i]
        i += 1

    return p

    # ZISTENIE ICMP TYPE-u
def find_icmp_type(val):
    p = ""
    i = 0

    while p == "" and i < len(ICMPprot[0]):
        if int(ICMPprot[0][i]) == val:
            p = ICMPprot[1][i]
        i += 1

    return p

    # PRIDANIE IP DO IP LISTU
def add_to_list(ip):
    new = True

    for i in range(len(IP_list[0])):
        if ip == IP_list[0][i]:
            IP_list[1][i] += 1
            new = False

    if new:
        IP_list[0].append(ip)
        IP_list[1].append(1)

    # NAJDENIE NAJCASTEJSIE ODOSIELAJUCEJ IP
def find_biggest():
    biggest = ""
    val = 0

    for i in range (len(IP_list[0])):
        if int(IP_list[1][i]) > val:
            val = IP_list[1][i]
            biggest = "{:<20}".format(IP_list[0][i]) + str(IP_list[1][i])

    return biggest

    # PRE 4.) A - F PRIDAVANIE DO LISTOV
def add_to_list_4(list, frame):
    assigned = False

    for i in range(len(list)):
        if (set([frame.d_ip, frame.s_ip]) == set([list[i][0].s_ip, list[i][0].d_ip]) and set([frame.d_port, frame.s_port]) == set([list[i][0].s_port, list[i][0].d_port])):
            list[i].append(frame)

            assigned = True

    if assigned == False:
        list.append([])
        list[len(list) - 1].append(frame)

    # PRIDAVANIE DO LISTU ARP
def add_to_list_4_ARP(list, frame):
    assigned = False

    for i in range(len(list)):
        if set([frame.d_ip, frame.s_ip]) == set([list[i][0].s_ip, list[i][0].d_ip]):
            if list[i][len(list[i])-1].flag == 2:
                continue

            list[i].append(frame)

            assigned = True

    if assigned == False:
        list.append([])
        list[len(list) - 1].append(frame)

    # PRELOZENIE TCP FLAG-u
def translate_tcp(num):
    comm= ["FIN", "SYN", "RST", "PSH", "ACK",]

    s = "["

    for i in range(5):
        if  num[i] == '1':
            s += comm[i] + ", "
    s = s[:-2] + "]"

    return s

    # VYPISOVANIE RAMCOV (Vytvaranie stringu s celym zarovanym vypisom)
def four_write(frame, type):
    s = ""

    s += ("\nFrame {}\n".format(frame.order))
    s += ("\tLenght (pcap API): \t\t {} B\n".format(frame.len_api))
    s += ("\tLenght (real): \t\t\t {} B\n".format(frame.len_real))
    s += ("\tDestination MAC: \t\t {}\n".format(frame.d_mac))
    s += ("\tSource MAC: \t\t\t {}\n".format(frame.s_mac))
    s += ("\tFrame type: \t\t\t Ethertype II\n")

    if frame.prot == "ARP":
        s += ("\tEtherType:  \t\t\t {}\n".format(frame.prot))
        s += ("\tOperation: \t\t\t {}\n".format("Request" if frame.flag == 1 else "Reply"))
        s += ("\tSender MAC: \t\t\t {}\n".format(frame.s_mac))
        s += ("\tTarget MAC: \t\t\t {}\n".format(frame.d_mac if frame.d_mac != "ff:ff:ff:ff:ff:ff" else "???"))
        s += ("\tSender IPv4: \t\t\t {}\n".format(frame.s_ip))
        s += ("\tTarget IPv4: \t\t\t {}\n".format(frame.d_ip))

    else:
        s += ("\tEtherType:  \t\t\t {}\n".format("IPv4"))
        s += ("\tSource IPv4: \t\t\t {}\n".format(frame.s_ip))
        s += ("\tDestination IPv4: \t\t {}\n".format(frame.d_ip))

        if frame.prot == "ICMP":
            s += ("\tIPv4 Protocol: \t\t\t {}\n".format(frame.prot))
            s += ("\tICMP Type: \t\t\t {}\n".format(frame.flag))
        else:
            if frame.prot == "TFTP":
                s += ("\tIPv4 Protocol: \t\t\t UDP\n")
            else:
                s += ("\tIPv4 Protocol: \t\t\t TCP\n")

            s += ("\tSource port: \t\t\t {}\n".format(frame.s_port))
            s += ("\tDestination port: \t\t {}\n".format(frame.d_port))
            s += ("\tPort protocol: \t\t\t {}\n".format(frame.prot))

    s += frame.hexagulas
    return s

    # ZISTOVANIE KOREKTNEHO ZACIATKU TCP KOMUNIKACIE
def check_start_tcp(list):
    start = None

        # SYN, SYN ACK, ACK
    for i in range(2, len(list)-1):
        if ( list[i-2].flag[1] == '1' and list[i-1].flag[1] == '1' and list[i-1].flag[4] == '1' and list[i].flag[4] == '1' ):
            start = i-2
            continue

    return start

    # ZISTOVANIE KOREKTNEHO KONCA TCP KOMUNIKACIE
def check_end_tcp(list):
    end = None

    for i in range(3, len(list)):

            # RST
        if list[i].flag[2] == '1':
            end = list[i]
            continue

        if i > 4 :
                # FIN ACK, ACK, FIN ACK, ACK
            if (list[i-3].flag[0] == '1' and list[i-3].flag[4] == '1' and list[i-2].flag[4] == '1' and  list[i-1].flag[0] == '1' and list[i-1].flag[4] == '1' and list[i].flag[4] == '1'):

                end = list[i - 3]
                continue

                # FIN, FIN ACK, ACK
            if (list[i - 2].flag[0] == '1' and list[i - 1].flag[0] == '1' and list[i - 1].flag[4] == '1' and list[i].flag[4] == '1'):
                end = list[i - 3]
                continue

    return end

    # URCOVANIE TFTP KOMUNIKACIE (pre vsetky ramce bez portu 69)
def check_tftp_communication(frame):

    if len(TFTP_l) > 0:
        for i in range(len(TFTP_l)):
            if set([TFTP_l[i][0].s_ip, TFTP_l[i][0].d_ip ]) == set([frame.d_ip, frame.s_ip]) and (TFTP_l[i][0].s_port == frame.d_port or TFTP_l[i][0].s_port == frame.s_port):
                TFTP_l[i].append(frame)
                return True
    return False

    # VYPIS A-F (prva nekompletna a jedna kompletna komunikacia)
def four_a_f_out(letter, out_file):
    global HTTP_l, HTTPS_l, TELNET_l, SSH_l, FTP_CONTROL_l, FTP_DATA_l

    complete = False
    incomplete= False

    list = eval((letter + "_l"), globals())

    if len(list)>0:
        out_file.write("\n{}\n".format("{}".center(80, "_").format(letter)))

        for i in range(len(list)-1):

            start = check_start_tcp(list[i]) # Pociatocny ramec komunikacie

            end = check_end_tcp(list[i])    # Koncovy ramec komunikacie

                # Kompletna komunikacia
            if end != None and start != None and complete == False:
                complete = True
                out_file.write("Complete communication: {}".center(80, "_").format(i+1))

                for j in range(start, len(list[i])):
                    if j < 10 or j > len(list[i])-11:
                        out_file.write("\nFlags:{} \n".format(translate_tcp(list[i][j].flag)))
                        out_file.write(four_write(list[i][j], letter))

                        out_file.write("\n")

                # Nekompletna komunikacia
            if start != None and end == None and incomplete == False:
                incomplete = True
                out_file.write("Incomplete communication: {}".center(80, "_").format(i + 1))

                for j in range(start, len(list[i])):
                    if j < 10 or j > len(list[i]) - 11:
                        out_file.write("\nFlags:{} \n".format(translate_tcp(list[i][j].flag)))
                        out_file.write(four_write(list[i][j], letter))

                        out_file.write("\n")

        if incomplete == False and complete == False:
            out_file.write("\tThis Protocol Has No Complete Nor Incomplete Communication")

    else:
        out_file.write("\nNo {} Frames\n".format(letter))

    # VOLANIE VSETKYCH A-F FUKNCII
def four_a_f(out_file):
    out_file.write("\n")
    out_file.write("4.) a - f".center(80, " "))
    out_file.write("\n")

    four_a_f_out("HTTP", out_file)
    four_a_f_out("HTTPS", out_file)
    four_a_f_out("TELNET", out_file)
    four_a_f_out("SSH", out_file)
    four_a_f_out("FTP_CONTROL", out_file)
    four_a_f_out("FTP_DATA", out_file)

    # ULOHA 4.) G (TFTP)
def four_g(out_file):
    out_file.write("\n")
    out_file.write("4.) g".center(80, " "))
    out_file.write("\n")

    if len(TFTP_l)>0:
        out_file.write("TFTP".center(80, "_"))

        for i in range(len(TFTP_l)):
            out_file.write("\n")
            out_file.write("Communication: {}".center(80, "_").format(i + 1))

            for j in range(len(TFTP_l[i])):
                if j < 10 or j > len(TFTP_l[i]) - 11:
                    out_file.write(four_write(TFTP_l[i][j], "TFTP"))

    else:
        out_file.write("\nNo TFTP communication\n")

    # ULOHA 4.) H (ICMP)
def four_h(out_file):
    out_file.write("\n")
    out_file.write("4.) h".center(80, " "))
    out_file.write("\n")

    if len(ICMP_l)>0:
        out_file.write("ICMP".center(80, "_"))

        for i in range(len(ICMP_l)):
            out_file.write("\n")
            out_file.write("Communication: {}".center(80, "_").format(i + 1))
            for j in range(len(ICMP_l[i])):
                if j < 10 or j > len(ICMP_l[i]) - 11:
                    out_file.write(four_write(ICMP_l[i][j], "ICMP"))
    else:
        out_file.write("No ICMP Frames\n")

    # ULOHA 4.) I (ARP)
def four_i(out_file):
    out_file.write("\n")
    out_file.write("4.) i".center(80, " "))
    out_file.write("\n")
    counter = 0

    if len(ARP_l)>0:
        for i in range(len(ARP_l)):

                # Zistovanie ci ide o Request, Reply alebo obidva
            if ARP_l[i][len(ARP_l[i]) - 1].flag == 1:
                line = "(Request)"
            elif len(ARP_l[i]) > 1:
                line = "(Request & Reply)"
                out_file.write("Communication: {}".center(80, "_").format(counter + 1))
                out_file.write("\n{}".format(line))
                out_file.write("\tFinding Target MAC for IP: {} \n".format(ARP_l[i][0].d_ip))
                counter += 1
            else:
                line = "(Reply)"
                out_file.write("Communication: {}".center(80, "_").format(counter + 1))
                out_file.write("\n{}".format(line))
                counter += 1

                # Vypis
            for j in range(len(ARP_l[i])):
                if ARP_l[i][len(ARP_l[i]) - 1].flag != 2:
                    out_file.write("Communication: {}".center(80, "_").format(counter + 1))
                    out_file.write("\n{}".format(line))
                    counter += 1

                out_file.write(four_write(ARP_l[i][j], "ARP"))

                # Ak ide o Request a Reply, vypise sa Cielova MAC adresa
            if ARP_l[i][len(ARP_l[i])-1].flag == 2 and len(ARP_l[i]) > 1:
                out_file.write("\nTarget MAC: {}\n\n".format(ARP_l[i][len(ARP_l[i])-1].s_mac))
            else:
                out_file.write("\n")
    else:
        out_file.write("No ARP Frames\n")

    # VOLANIE JEDNOTLIVYCH CASTI ULOHY 4
def four_f(out_file):

    four_a_f(out_file)
    four_g(out_file)
    four_h(out_file)
    four_i(out_file)

    out_file.close()
    os.startfile(out_file.name) # Po skonceni otvorenie suboru s ulohou 4

    # "UI"
def info():
    print("I N F O R M A T I O N".center(60, " "),
          "\ne- Exit",
          "\nf- Files",
          "\ni- Information",
          "\nl- Load ETH & IEE & IP & PORT",
          "\nfour- Make task 4"
          )

#.................................................M.A.I.N..............................................................#

def main():

        #Pred spustenim programu je vhodne umiestnit do priecinka "Pcap" subory urcene na testovanie
    for f in listdir(".\\Pcap\\"):
        files.append(f)

    info()

        # Pociatocne nacitanie poli z externych suborov
    loadProt("ETH")
    loadProt("IEEE")
    loadProt("IP")
    loadProt("PORT")
    loadProt("ICMP")

        # Loop Programu
    try:
        while True:
            arp_ctr = 0
            num_file = input("\n\nPlease enter file number:\n") # Pouzivatelsky vstup z klavesnice

                # Ukonci program  'e' - exit
            if num_file == 'e':
                break

                # Pre lepsiu prehladnost vypise vsetky mozne subory na testovanie 'f' - files
            if num_file == 'f':
                for i in range (len(files)):
                    if i % 5 == 0 and i > 0:
                        print("")
                    print("\t", i+1, "- ", end="")
                    print( '{:>20}'.format(files[i]), end="")
                continue

                # Vypis informacii 'i' - information
            if num_file == "i":
                info()
                continue

                # Znovu nacitanie z externych suborov za chodu programu (pridanie protokolov) 'l' - load
            if num_file == "l":
                loadProt("ETH")
                loadProt("IEEE")
                loadProt("IP")
                loadProt("PORT")
                loadProt("ICMP")
                continue

                # Uloha 4
            if num_file == "four":
                try:
                    out_file.name != ""
                    print("Working on 4. ")
                    out_file_f = open(out_file.name[:-4] + "_4_Uloha.txt", "w")
                    out_file_f.close()
                    out_file_f = open(out_file.name[:-4] + "_4_Uloha.txt", "a")
                    four_f(out_file_f)
                    print("Check output file")
                except UnboundLocalError:
                    print("Analyze file, then try this.")
                continue

                # Kontrola vstupu + praca s suborom na vypis
            try:
                if num_file.isnumeric():
                    print("Loading frames from pcap folder")
                    file = rdpcap(f_path + files[int(num_file)-1])
                    out_file = open(".\\Out\\" + files[int(num_file)-1][:-4] + "txt", "w")
                    line = "ANALYZATOR SUBORU " + out_file.name[11:]
                    out_file.write(line.center(80, "_"))
                    print("Progress")
                    print("Start", 22 * " ", "End")
                        # Pri zmene testovacieho suboru sa precistia polia
                    IP_list[0].clear()
                    IP_list[1].clear()
                    HTTP_l.clear()
                    HTTPS_l.clear()
                    TELNET_l.clear()
                    SSH_l.clear()
                    FTP_CONTROL_l.clear()
                    FTP_DATA_l.clear()
                    TFTP_l.clear()
                    ICMP_l.clear()
                    ARP_l.clear()
                else:
                    print("Chybny vstup")
                    continue
            except IndexError:
                print("No such test file\n\tTry 'f'")
                continue

                # Pri zmene testovacieho suboru je potrebne vycistit pole s ramcami
            frames.clear()
            for frame in file:
                frames.append(raw(frame))

            print("|", 28*" ", "|\n|", end="")
            x = 0 # Poradove cislo ramca
            p = 3.3
                # Vypis do konzoly a zaroven do subora (konzola nevypise niektore testovacie subory z dovodu dlzky)
            for x in range(len(frames)):
                y = 0   #Riadok v hexa vypise
                r = 1   #Hexa poradie riadku

                    # Protokoly 3. vrstvy
                global ETH_p
                ETH_p = ""
                global IEEE_p
                IEEE_p = ""

                    # Odsadenie medzi ramcami
                if x > 0:
                    line = 80 * "_"
                    out_file.write(line)
                else:
                    out_file.write("\n")

                    # Analyza + vypis ramca
                frame_order = x + 1     # Poradie Ramca
                out_file.write("\nFrame {}\n".format(frame_order))

                len_api = len(frames[x])        # Dlzka ramca cez pcap API
                out_file.write("\tLenght (pcap API): \t\t {} B\n".format(len_api))

                len_real = real_len(frames[x])      # Dlzka ramca prenasana po mediu
                out_file.write("\tLenght (real): \t\t\t {} B\n".format(len_real))

                d_mac = mac_out(binascii.hexlify(frames[x]).decode()[0: 12])        # Cielova MAC adresa
                out_file.write("\tDestination MAC: \t\t {}\n".format(d_mac))

                s_mac = mac_out(binascii.hexlify(frames[x]).decode()[12: 24])       # Zdrojova MAC adresa
                out_file.write("\tSource MAC: \t\t\t {}\n".format(s_mac))

                frame_t = frame_type(binascii.hexlify(frames[x]).decode())      # Typ protokolu 2. vrstvy
                out_file.write("\tFrame type: \t\t\t {}\n".format(frame_t))

                    # HEXAGULAS - naplnenei stringu
                h = ""
                for z in range(len(binascii.hexlify(frames[x]).decode()) + 1):
                    if y > 0:
                        h += (binascii.hexlify(frames[x]).decode()[z - 1])
                        if y % 2 == 0:
                            h += (" ")
                        if y % 16 == 0:
                            h += (" ")
                        if y % 32 == 0:
                            h += ("\n")
                            h += (hex(r * 16)[2:].rjust(4, "0"))
                            h += (": ")
                            r += 1
                    else:
                        h += ("\n")
                        h += (hex(0)[2:].rjust(4, "0"))
                        h += (": ")
                    y += 1
                h += ("\n")

                    # ETH
                if ETH_p != "":
                    out_file.write("\tEtherType:  \t\t\t {}\n".format(ETH_p))

                        # IPv4
                    if ETH_p == "IPv4":
                        s_ip = ip_out(binascii.hexlify(frames[x]).decode()[52: 60])     # Zdrojova IP
                        out_file.write("\tSource IPv4: \t\t\t {}\n".format(s_ip))

                        add_to_list(s_ip)       # Pridanie zdrojovej IP do pola

                        d_ip = ip_out(binascii.hexlify(frames[x]).decode()[60: 68])     # Cielova IP
                        out_file.write("\tDestination IPv4: \t\t {}\n".format(d_ip))

                        prot_ip = find_ip_prot(binascii.hexlify(frames[x]).decode()[46: 48])    # Typ protokolu 4. vrstvy
                        out_file.write("\tIPv4 Protocol: \t\t\t {}\n".format(prot_ip))
                        IHL = int(binascii.hexlify(frames[x]).decode()[29], 16)  # IHL cast IP hlavicky

                            # TCP || UDP
                        if prot_ip == "TCP" or prot_ip == "UDP":

                            s_port = int(binascii.hexlify(frames[x]).decode()[28 + IHL*4*2: 28 + IHL*4*2+4], 16)        # Zdrojovy port v int
                            d_port = int(binascii.hexlify(frames[x]).decode()[28 + IHL*4*2+4: 28 + IHL*4*2+8], 16)      # Cielovy port v int

                            try :
                                flag = bin(int(binascii.hexlify(frames[x]).decode()[28 + IHL*4*2 + 26: 28 + IHL*4*2+28], 16))
                            except ValueError:
                                pass

                            flag = str(flag)[::-1][:-2] + "00000"

                            out_file.write("\tSource port: \t\t\t {}\n".format(s_port))
                            out_file.write("\tDestination port: \t\t {}\n".format(d_port))

                            prot_port = find_PORT(s_port) if s_port < d_port else find_PORT(d_port)     # Typ protokolu 7. vrstvy

                                # Posielanie Ramcov na zapis do poli (potrebne na ulohu 4)
                            if prot_port != "":
                                out_file.write("\tPort protocol: \t\t\t {}\n".format(prot_port))
                                try:
                                    prott = prot_port.upper()
                                    list_4 = eval(prott + "_l")
                                    frame_4 = FRAME(frame_order, len_api, len_real, d_mac, s_mac, d_ip, s_ip, prott, h, flag, d_port, s_port)
                                    add_to_list_4(list_4, frame_4)
                                except NameError:
                                    pass
                            else:
                                frame_4 = FRAME(frame_order, len_api, len_real, d_mac, s_mac, d_ip, s_ip, "TFTP", h, flag, d_port, s_port)
                                if check_tftp_communication(frame_4) == True:
                                    out_file.write("\tPort protocol: \t\t\t TFTP\n")

                            # ICMP predpriprava na ulohu 4
                        if prot_ip == "ICMP":
                            list_4 = eval("ICMP" + "_l")
                            icmp_type = int(binascii.hexlify(frames[x]).decode()[28 + IHL*4*2: 28 + IHL*4*2+2], 16)
                            icmp_type_o = find_icmp_type(icmp_type)
                            out_file.write("\tICMP Type: \t\t\t {}\n".format(icmp_type_o))

                            frame_4 = FRAME(frame_order, len_api, len_real, d_mac, s_mac, d_ip, s_ip, "ICMP", h, icmp_type_o)
                            add_to_list_4(list_4, frame_4)

                        # ARP
                    elif ETH_p == "ARP":
                        op_code = int(binascii.hexlify(frames[x]).decode()[40: 44])
                        out_file.write("\tARP Operation: \t\t\t {}\n".format("Request" if op_code == 1 else "Reply"))

                        arp_s_mac = mac_out(binascii.hexlify(frames[x]).decode()[44: 56])
                        out_file.write("\tSender MAC: \t\t\t {}\n".format(arp_s_mac))

                        arp_d_mac = mac_out(binascii.hexlify(frames[x]).decode()[64: 80])
                        arp_d_mac_raw = binascii.hexlify(frames[x]).decode()[64: 76]
                        out_file.write("\tTarger MAC: \t\t\t {}\n".format(arp_d_mac if int(arp_d_mac_raw,16) != 0 else "???"))

                        s_ip = ip_out(binascii.hexlify(frames[x]).decode()[56: 64])
                        out_file.write("\tSender IPv4: \t\t\t {}\n".format(s_ip))

                        d_ip = ip_out(binascii.hexlify(frames[x]).decode()[76: 84])
                        out_file.write("\tTarget IPv4: \t\t\t {}\n".format(d_ip))

                        list_4 = eval("ARP" + "_l")
                        frame_4 = FRAME(frame_order, len_api, len_real, d_mac, s_mac, d_ip, s_ip, "ARP", h, op_code)
                        add_to_list_4_ARP(list_4, frame_4)

                    #IEEE
                if IEEE_p != "":
                    out_file.write("\tIEEE SAPs: \t\t\t {}\n".format(IEEE_p))

                    # HEXAGULAS VYPIS
                out_file.write(h)

                    # Progress Bar
                if ((x + 1) / len(frames) * 100 > p ):
                    print(".", end="")
                    p += 3.3

            if x == len(frames)-1:
                print("|", end="")

                # Tretia Uloha
            out_file.write("\n\nSource IP adresses: ({} packets from {} IP adresses)\n".format(sum(IP_list[1]), len(IP_list[0])))

            for i in range(len(IP_list[0])):
                out_file.write("\t\t{:<20}{:<5}\n".format(IP_list[0][i], IP_list[1][i]))

            line = "\tBiggest:\n\t\t{}\n"
            out_file.write(line.format(find_biggest()))
    # Koniec Tretej Ulohy

            print("\nDone, check .txt output file")

            out_file.close()

            os.startfile(out_file.name) # OTVARANIE .txt SUBOROV

    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()