'''
@Description: Real time modbus packet parsed and the result written to csv file
@Requirement: pyshark
@Author: FST
'''

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

from mac_vendor_lookup import MacLookup
import sqlite3
import pyshark
from traceback import format_exc


class PacketParser:
    def __init__(self):
        self.function_codeA = []
        self.liste = []
        self.pretty_format = []
        self.initial_state()

    def initial_state(self):

        self.func_code = 0
        self.func_codeS = ""

    def packet_parse(self, raw_packet):
        self.initial_state()

        if 'ETH' in raw_packet:
            pass
        if 'IP' in raw_packet:
            pass
        if 'TCP' in raw_packet:
            pass
        if 'MBTCP' in raw_packet:
            pass
        if 'MODBUS' in raw_packet:

            try:
                modbus_packet = str(raw_packet['MODBUS'])
                parsing_modbus_packet = modbus_packet.split('\n')
                modbus_packet2 = raw_packet['MODBUS']

                self.func_code = modbus_packet2.func_code
                self.func_codeI = int(self.func_code)

                if self.func_codeI == 1:
                    self.func_codeS = "Read Coil"
                    #print(self.func_codeS)
                elif self.func_codeI == 2:
                    self.func_codeS = "Read Discrete Input"
                    #print(self.func_codeS)
                elif self.func_codeI == 3:
                    self.func_codeS = "Read Holding Register"
                    #print(self.func_codeS)
                elif self.func_codeI == 4:
                    self.func_codeS = "Read Input Register"
                    #print(self.func_codeS)
                elif self.func_codeI == 5:
                    self.func_codeS = "Write Single Coil"
                    #print(self.func_codeS)
                elif self.func_codeI == 6:
                    self.func_codeS = "Write Single Holding Register"
                    #print(self.func_codeS)
                elif self.func_codeI == 7:
                    self.func_codeS = "Read Exception Status"
                    #print(self.func_codeS)
                elif self.func_codeI == 8:
                    self.func_codeS = "Diagnostics"
                    #print(self.func_codeS)
                elif self.func_codeI == 11:
                    self.func_codeS = "Get Comm Event Counter"
                    #print(self.func_codeS)
                elif self.func_codeI == 12:
                    self.func_codeS = "Get Comm Event Log"
                    #print(self.func_codeS)
                elif self.func_codeI == 15:
                    self.func_codeS = "Write Multiple Coils"
                    #print(self.func_codeS)
                elif self.func_codeI == 16:
                    self.func_codeS = 'Write Multiple Holding Register'
                    #print(self.func_codeS)
                elif self.func_codeI == 17:
                    self.func_codeS = "Report Slave ID"
                    #print(self.func_codeS)
                elif self.func_codeI == 20:
                    self.func_codeS = "Read File Record"
                    #print(self.func_codeS)
                elif self.func_codeI == 21:
                    self.func_codeS = "Write File Record"
                    #print(self.func_codeS)
                elif self.func_codeI == 22:
                    self.func_codeS = "Mask Write Register"
                    #print(self.func_codeS)
                elif self.func_codeI == 23:
                    self.func_codeS = "Read/Write Multiple registers"
                    #print(self.func_codeS)
                elif self.func_codeI == 24:
                    self.func_codeS = "Read FIFO Queue"
                    #print(self.func_codeS)
                elif self.func_codeI == 43:
                    self.func_codeS = "Encapsulated Interface Transport"
                    #print(self.func_codeS)

            except:
                format_exc()

            try:
                sayac = 0
                while True:
                    if (self.func_codeS not in self.function_codeA):
                        self.function_codeA.append(self.func_codeS)

                        self.liste.append(self.func_codeS)

                        for i in range(len(self.function_codeA)):
                            sayac = sayac + 1
                        print(sayac)

                        if self.function_codeA.__len__() >= sayac:
                            print(self.function_codeA)
                            for fc in self.function_codeA:
                                print(fc)

                        if self.function_codeA.__len__() >= sayac:
                            # print(self.liste)
                            n = 1
                            final = [self.liste[i * n:(i + 1) * n] for i in range((len(self.liste) + n - 1) // n)]
                            # print(final)
                            cursor.execute("Select * From funcCode")
                            listen_func_code = cursor.fetchall()

                            result = []
                            for s in listen_func_code:
                                for x in s:
                                    result.append(x)
                            final2 = [result[i * n:(i + 1) * n] for i in range((len(result) + n - 1) // n)]
                            print(final2)
                            for j in range(final.__len__()):
                                if final2.__len__() == 0:
                                    cursor.execute("insert into funcCode values (?)", final[j])
                                    con.commit()
                                elif final[j] not in final2:
                                    cursor.execute("insert into funcCode values (?)", final[j])
                                    con.commit()

                    elif self.func_codeS in self.function_codeA:
                        break
            except:
                format_exc()
#def tablo_olustur():
 #   cursor.execute("CREATE TABLE IF NOT EXISTS funcCode (funcCode TEXT)")
  #  con.commit()

if __name__ == '__main__':

    parser = PacketParser()
    con = sqlite3.connect("listen_func_code.db")

    cursor = con.cursor()  # veri tababnındaki işlemleri yapmaya yarıyor
    #tablo_olustur()
    # veri_ekle()
    # con.close()
    try:
        capture = pyshark.LiveCapture(interface='ens33')
        for pkt in capture.sniff_continuously(packet_count=5000):
            parser.packet_parse(pkt)
            # parser.sayac_olusturma(pkt)
        con.close()
        print("bitti")
    except:
        print(format_exc())

