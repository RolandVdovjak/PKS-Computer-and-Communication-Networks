import zlib
import socket
import os
import struct
import time
import threading

#Moje IP na LAN z dovodu nevypisovania zakazdym
IP_LAPTOP = '192.168.0.101'
IP_PC = '192.168.0.104'
PORT = 1234
host = socket.gethostbyname(socket.gethostname())

fragment_size = -1
thread_sending_KA = False
thread_work = True
sec = 5    # TIME between KA messagess
wrong_fragments = [2,3,6,8]     # Pole indexov na kt sa vyskytne chybny fragment

# POSIELANIE KEEP ALIVE
def sending_ka(client_s, server_address):
    global thread_sending_KA, sec
    counter = 0

    # Kym je thread_work pravdiva, vykonava sa cyklus
    while thread_work:
        time.sleep(1)   # Neskusa dookola vstupit do dalsieho cyklu ale iba kazdu sekundu

        # Posielanie keep alive
        while thread_sending_KA:
            client_s.sendto(get_header(8), server_address)      # Posielanie KEEP ALIVE hlavicky

            # Cakanie na prijatie potvrdenia spojenia
            try:
                data, addr = client_s.recvfrom(1500)
                counter = 0
                data_text, data_int = translate(data[0])

                if data_int == 16:
                    thread_sending_KA = False
                    print("Server sa odpojil. Pre ukoncenie zadaj: 3")
                counter = 0
            except socket.timeout:
                counter +=1

            # Minimalne 30sekund neprisla odpoved (30-40s)
            if counter == 3:
                client_s.sendto(get_header(16), server_address)
                thread_sending_KA = False
                print("Server neodpoveda. Pre ukoncenie zadaj: 3")

            if counter == 0:
                time.sleep(sec)

# FUNKCIA FRACIA CRC PARAMETRA
def crc(data):
    crc_val = zlib.crc32(data)
    return crc_val

# PRREKLADA FLAG DO CISLA A TEXTU
def translate(type):
    type_translated = "Wrong type"

    # Podla hodnoty flagu sa rozhoduje aku funkciu ma ramec
    if type == 1:
        type_translated = "Connection start"
    elif type == 2:
        type_translated = "Fragment recieved"
    elif type == 4:
        type_translated = "Fragment redjected"
    elif type == 8:
        type_translated = "Keep alive"
    elif type == 16:
        type_translated = "Connection end"
    elif type == 32:
        type_translated = "Connection confirmed"
    elif type == 64:
        type_translated = "Sending data"
    elif type == 128:
        type_translated = "Sending text"
    elif type == 65:
        type_translated = "File Name"
    return type_translated, type

# POSIELANIE HLAVICKY LEN S FLAGOM
def get_header(typ):
    type = typ
    blank = 0
    header = type.to_bytes(1, byteorder='big') + blank.to_bytes(8, byteorder='big')

    return header

# KONTROLA VELKOSTI FRAGMENTU
def check_frag_size():
    global fragment_size

    # Dokym nebude koretne zadana velkost opakuje sa cyklus
    while fragment_size < 1 or fragment_size > (1500-9-20-8):
        print("Zla velkosti.")
        fragment_size = int(input("Zadaj znovu velkost fragmentu: "))

# NACITAVA VIACRIADKOVY STRING
def load_text_msg():
    text = """"""

    while True:
        line = input()

        if line and line !='$':
            text += line + " "
        if line == '$':     # Dolar je ukoncovaci znak vstupu
            break
        else:
            text += "\n"

    return text

# ODOSLANIE
def send(f_type, client_s, server_address):
    global fragment_size, thread_sending_KA, wrong_fragments

    # Posiela sa subor
    if f_type == '1':
        f_path = input("Zadaj cestu k suboru.\n")
        f = open(f_path, 'rb')
        f_name = (os.path.basename(f_path)).encode('utf-8')

        # odoslanie mena suboru
        h_type = 65
        h_crc = crc(f_name)
        h_frag_num = 0
        h_size = len(f_name)
        frag_full = h_type.to_bytes(1, byteorder='big') + h_size.to_bytes(2, byteorder='big') + h_frag_num.to_bytes(2, byteorder='big') + h_crc.to_bytes(4, byteorder='big') + f_name
        print("Posielam meno suboru")
        client_s.sendto(frag_full, server_address)  # Odoslanie

        size = os.path.getsize(f_path)
        data = f.read()
        h_type = 64

    # Posiela sa textova sprava
    if f_type == '2':
        print("Zadaj text spravy.\n")
        text_msg = load_text_msg()
        data = text_msg.encode('utf-8')
        size = len(data)
        h_type = 128

    # Fragment
    fragment_size = int(input("Velkost jedneho fragmentu: "))
    check_frag_size()

    # Zistenie poctu fragmentov
    number_of_frag = int(size / fragment_size)
    if size % fragment_size != 0:
        number_of_frag += 1

    if number_of_frag > 65534:
        v = int(size / 65534) + 1
        print("Velkost fragmentu je moc mala, na prenesenie suboru je minimalna velkost: ", v)
        fragment_size = int(input("Velkost jedneho fragmentu vacsiu ako {}: ".format(v)))
        number_of_frag = int(size / fragment_size)
        if size % fragment_size != 0:
            number_of_frag += 1

    # Inicializovanie potrebnych premennych
    h_frag_num = 0
    type_text = ""
    type_int = 0
    sended = True

    # Vypnut thread s KEEPALIVE
    thread_sending_KA = False

    # Odoslanie
    while True:
        frag_data = bytearray(data[h_frag_num * fragment_size : (h_frag_num+1) * fragment_size])   # Data poslane fragmentom
        h_size = len(frag_data)           # Velkost fragmentu
        h_frag_num += 1     # Poradie fragmentu

        h_crc = crc(frag_data)  # crc

        # Posielanie chyb
        if sended and h_frag_num in wrong_fragments:
            original_byte = frag_data[0]
            frag_data[0] = 0

        #Zlozenie fragmentu
        frag_full = h_type.to_bytes(1, byteorder='big') + h_size.to_bytes(2, byteorder='big') + h_frag_num.to_bytes(2, byteorder='big') + h_crc.to_bytes(4, byteorder='big') + frag_data

        print("Posielam ramec cislo: {}".format(h_frag_num))
        client_s.sendto(frag_full, server_address)  # Odoslanie

        fragment, addr = client_s.recvfrom(1500)  # FRAGMENT od klienta

        type_text, type_int = translate(fragment[0])

        if type_int == 32:
            fragment, addr = client_s.recvfrom(1500)
            type_text, type_int = translate(fragment[0])

        # Fragment prijaty
        if type_int == 2:
            sended = True
            print("Flag ramca:", type_text)

        # Fragment odmietnuty
        if type_int == 4:
            print("Flag ramca:", type_text, "\nPosielam znovu")
            frag_data[0] = original_byte
            sended = False
            h_frag_num-=1
            continue

        # Odoslane vsetko
        if h_frag_num == number_of_frag:
            client_s.sendto(get_header(8), server_address)
            if h_type == 64:
                print("Poslany subor: {}\n".format(os.path.abspath(f_path)) +
                      "Velkost: {} B".format(size))
            else:
                print("Poslany text\n" +
                      "Velkost: {} B".format(size))

            # Zapnutie KEEPALIVE
            thread_sending_KA = True
            break

# KLIENT
def client():
    global thread_sending_KA, thread_work
    while True:

        print("Pre pripojenie zadaj udaje\n")
        ip = input("IP Servera: ")
        port = int(input("PORT Servera: "))

        # Pripaja sa na server
        try:
            client_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_address = (ip, port)
            client_s.sendto(get_header(1), server_address)
            client_s.settimeout(30)
            data, address = client_s.recvfrom(1500)

            # Po pripojeni spusti moznosti
            if data == get_header(1):
                print("Pripojene ku: {}\n".format(address))
                client_s.settimeout(10)
                # Vlakno s Keep Alive
                thread = threading.Thread(target=sending_ka, args=(client_s, server_address))
                thread_work = True
                thread.start()

                while True:
                    # Start keep alive
                    thread_sending_KA = True
                    choose_C()
                    print("\nVybrat rolu nanovo[Y], inak zvol rezim [vyber cislo]\n")
                    choosed = input()

                    # Pouzivatel chce zmenit rolu
                    if choosed == 'Y':
                        return

                    # Klient chce odoslat subor
                    if choosed == '1':
                        send('1', client_s, server_address)

                    # Klient chce odoslat text
                    if choosed == '2':
                        send('2', client_s, server_address)

                    # Ukoncenie spojenia
                    if choosed == '3':
                        print("Ukoncujem spojenie")
                        client_s.sendto(get_header(16), server_address)
                        thread_sending_KA = False
                        thread_work = False
                        thread.join()
                        break

                if choosed == '3':
                    break

            else:
                print("Chyba spojenia.\n\n")
                continue

        except (socket.timeout, ConnectionError, ConnectionResetError):
            print("Nepodarilo sa pripojit na server.\n\n")
            continue

# SERVER
def server():
    while True:
        choose_S()
        server_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port = int(input("Zadaj port: "))
        server_s.bind((host, port))
        print("Cakanie na klienta...")

        # Caka na spojenie
        try:
            server_s.settimeout(10)
            data, address = server_s.recvfrom(1500)

            # Overenie zaciatku spojenia
            if data == get_header(1):
                server_s.sendto(get_header(1), address)
                server_s.settimeout(10)
            else:
                print("Neuspesne pripojenie")
                continue

            print("Pripojene ku: {}\n".format(address))

            choosed = ''
            while True:

                print("\nPokracovat [Enter], Vymena roli alebo koniec programu [0], Spustenie servera na novo [1]\n")
                choosed = input()
                # Pouzivatel chce zmenit rolu
                if choosed == '0':
                    server_s.sendto(get_header(16), address)
                    server_s.close()
                    return
                elif choosed == '1':
                    break

                data = ""
                last_type_int = ""
                hexdumb = b""
                frag_num = 0
                data_size = 0
                print("Server je pripraveny.\n")

                server_s.settimeout(30)
                # Pocuvanie Servera
                while True:

                    try:
                        fragment, addr = server_s.recvfrom(1500) # FRAGMENT od klienta

                        type_text, type_int = translate(fragment[0])

                        # Vypis flagu fragmentu
                        if type_int != 8:
                            print("Flag fragmentu: ", type_text)

                        # Ukoncenie spojenia
                        if type_int == 16:
                            print("V nasledujucej volbe stlac [0] alebo [1]")
                            break

                        # KEEPALIVE + odpoved
                        if type_int == 8:
                            server_s.sendto(get_header(32), address)

                        # Meno suboru
                        if type_int == 65:
                            if crc(fragment[9:]) == int.from_bytes(fragment[5:9], byteorder='big'):
                                file_name = fragment[9:].decode()

                        # Kontrola crc
                        if type_int == 64 or type_int == 128:
                            if crc(fragment[9:]) == int.from_bytes(fragment[5:9], byteorder='big'):
                                frag_size = int.from_bytes(fragment[1:3], byteorder='big')
                                print("Fragment cislo {} o velkosti {} sedi\n".format(int.from_bytes(fragment[3:5], byteorder='big'), frag_size))
                                server_s.sendto(get_header(2), address)
                                hexdumb += fragment[9:]
                                frag_num += 1
                                data_size += (frag_size)
                            else:
                                print("Fragment nesedi\n")
                                server_s.sendto(get_header(4), address)

                        # Odoslanie celeho suboru
                        if type_int == 8 and (last_type_int == 64 or last_type_int == 128):
                            print("\nSprava bola odoslana cela.")
                            if last_type_int == 128:
                                data = hexdumb.decode('utf-8')
                                print("Text spravy:\n")
                                print(data)
                            else:
                                save_path = input("Zadaj cestu, kde sa ulozi subor. Pre domovsky priecinok [Enter]\n")
                                file = open(save_path + file_name, 'wb')

                                file.write(hexdumb)
                                file.close()
                                print("Ulozene v {}".format(os.path.abspath(save_path + file_name)))
                                print("Pocet fragmentov: {}\n".format(frag_num) +
                                      "Velkost: {} B".format(data_size))

                            hexdumb = b""
                            frag_num = 0
                            data_size = 0
                            break

                        last_type_int = type_int

                    except socket.timeout:
                        print("Klien neaktivny, odpajam...\n")
                        break


        except socket.timeout:
            print("Nikto sa nepripojil.\n\n")
            server_s.close()
            return

# MENU vyberu Klient/Server
def choose_C_or_S():
    print("VYBER".center(50, '_'))
    print("Klient:  1\n"
          "Server:  2\n"
          "Exit:  3\n")

# MENU Server
def choose_S():
    print("SERVER".center(50, '_'))

# MENU Klient
def choose_C():
    print("KLIENT".center(50, '_'))
    print("\nOdoslat subor:  1\n"
          "Odoslat text:  2\n"
          "Koniec spojenia so serverom:  3")

#_______________________________M_A_I_N_______________________________#
def main():

    # Hlavny cyklus celeho programu
    while True:
        #Info + input
        choose_C_or_S()
        choosed = input("Vyber si: ")

        # Rozhodovanie podla inputu
        if choosed == '1':
            client()    # Klient
        elif choosed == '2':
            server()    # Server
        elif choosed == '3':
            break       # Exit
        else:
            print("Chybny vstup. Skus to znovu")

if __name__ == '__main__':
    main()