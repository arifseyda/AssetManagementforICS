'''
@Description: Real time modbus packet parsed and the result written to csv file
@Requirement: pyshark
@Author: FST
'''

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '


DATA_TAB_1 ='\t '
DATA_TAB_2 ='\t\t '
DATA_TAB_3 ='\t\t\t '
DATA_TAB_4 ='\t\t\t\t '

from mac_vendor_lookup import MacLookup
import sqlite3
import pyshark
from traceback import format_exc
import subprocess
import tempfile

class PacketParser:
    def __init__(self):
        self.ipadress = []
        self.macadress = []
        self.venderName = []
        self.liste = []
        self.pretty_format = []
        self.type_array = []
        self.protocol_name_array = []
        self.id_array = []
        self.location_array = []
        self.process_array = []
        self.ot_product_array = []
        self.ot_sytem_array = []
        self.segment_array = []
        self.sayac3 = 0
        self.module_array = []
        self.basic_hardware_array = []
        self.version_array = []
        self.system_name_array = []
        self.module_type_array = []
        self.serial_number_array = []
        self.copyrigthh_array = []
        self.initial_state()

    def initial_state(self):
        self.src_ip = ""
        self.src_mac = ""
        self.dst_mac = ""
        self.vender_name = ""
        self.type = ""
        self.type_name = ""
        self.func_code = 0
        self.layer_name = ""
        self.src_port = 0
        self.protocol_name = ""
        self.id = 0
        self.location = ""
        self.process = ""
        self.ot_product = ""
        self.ot_sytem = ""
        self.segment = ""
        self.module = ""
        self.basic_hardware = ""
        self.version = ""
        self.system_name = ""
        self.module_type = ""
        self.serial_number = ""
        self.copyrigthh = ""

    def packet_parse(self, raw_packet):
        self.initial_state()

        if 'ETH' in raw_packet:
            eth_header = raw_packet['ETH']
            self.src_mac = eth_header.src
            self.type = eth_header.type
            self.source_mac = self.src_mac
            self.vender_name = MacLookup().lookup("{}".format(self.src_mac))

            if self.vender_name == "SIEMENS AG":
                with tempfile.TemporaryFile() as tempf:
                    proc = subprocess.Popen(['nmap', '--script', 's7-info.nse', '-p', '102', '192.168.41.10'], stdout=tempf)
                    proc.wait()
                    tempf.seek(0)
                    nmap_answer_array = []

                    for i in range(0, 16):
                        nmap_answer = str(tempf.readline())
                        nmap_answer_array.append(nmap_answer)
                    # print(tempf.readlines())

                modulee = ''
                basic_hadwaree = ''
                versionn = ''
                system_namee = ''
                module_typee = ''
                serial_numberr = ''
                copyrigthhh = ''

                for item in nmap_answer_array:
                    if 'Module:' in item:
                        modulee = item
                        module2 = modulee.split(':')
                        module_numb_rep = module2[1]
                        self.module = module_numb_rep.replace(' \\n\'', '')
                        print(self.module)

                    if 'Basic Hardware' in item:
                        basic_hadwaree = item
                        basic_hadware2 = basic_hadwaree.split(':')
                        basic_hadware_rep = basic_hadware2[1]
                        self.basic_hardware = basic_hadware_rep.replace(' \\n\'', '')
                        print(self.basic_hardware)

                    if 'Version' in item:
                        versionn = item
                        version2 = versionn.split(':')
                        version_rep = version2[1]
                        self.version = version_rep.replace('\\n\'', '')
                        print(self.version)

                    if 'System Name' in item:
                        system_namee = item
                        system_name2 = system_namee.split(':')
                        system_name_rep = system_name2[1]
                        self.system_name = system_name_rep.replace('\\n\'', '')
                        print(self.system_name)

                    if 'Module Type' in item:
                        module_typee = item
                        module_type2 = module_typee.split(':')
                        module_type_rep = module_type2[1]
                        self.module_type = module_type_rep.replace('\\n\'', '')
                        print(self.module_type)

                    if 'Serial Number' in item:
                        serial_numberr = item
                        serial_number2 = serial_numberr.split(':')
                        serial_number_rep = serial_number2[1]
                        self.serial_number = serial_number_rep.replace('\\n\'', '')
                        print(self.serial_number)

                    if 'Copyright' in item:
                        copyrigthhh = item
                        copyrigthh2 = copyrigthhh.split(':')
                        copyrigthh_rep = copyrigthh2[1]
                        self.copyrigthh = copyrigthh_rep.replace('\\n\'', '')
                        print(self.copyrigthh)

            cursor2.execute("Select * From ether_type")
            ether_type = cursor2.fetchall()
            result = []
            for s in ether_type:
                for x in s:
                    result.append(x)
            n = 2
            final2 = [result[i * n:(i + 1) * n] for i in range((len(result) + n - 1) // n)]
            for i in final2:
                if self.type == i[0]:
                    self.type_name = i[1]

            if self.type_name == "LLDP" or self.type_name == "Profinet" or self.type_name == "Ethercat"\
                    or self.type_name == "GOOSE":
                try:
                    liste_id_haric = []
                    sayac = 0
                    sayac2 = 0
                    while True:
                        self.src_ip = '-'
                        self.src_port = '-'
                        self.protocol_name = self.type_name
                        if (self.src_ip not in self.ipadress) or (self.src_mac not in self.macadress) \
                                or (self.vender_name not in self.venderName) or (self.type_name not in self.type_array) \
                                or (self.protocol_name not in self.protocol_name_array):

                            self.ipadress.append(self.src_ip)
                            for i in range(len(self.ipadress)):
                                sayac = sayac + 1
                                self.sayac3 += 1
                            self.macadress.append(self.src_mac)
                            self.venderName.append(self.vender_name)
                            self.type_array.append(self.type_name)
                            self.protocol_name_array.append(self.protocol_name)
                            self.location_array.append(self.location)
                            self.process_array.append(self.process)
                            self.ot_product_array.append(self.ot_product)
                            self.ot_sytem_array.append(self.ot_sytem)
                            self.segment_array.append(self.segment)
                            self.module_array.append(self.module)
                            self.basic_hardware_array.append(self.basic_hardware)
                            self.version_array.append(self.version)
                            self.system_name_array.append(self.system_name)
                            self.module_type_array.append(self.module_type)
                            self.serial_number_array.append(self.serial_number)
                            self.copyrigthh_array.append(self.copyrigthh)

                            self.liste.append(self.src_mac)
                            self.liste.append(self.src_ip)
                            self.liste.append(self.vender_name)
                            self.liste.append(self.type_name)
                            self.liste.append(self.protocol_name)
                            self.liste.append(self.location)
                            self.liste.append(self.process)
                            self.liste.append(self.ot_product)
                            self.liste.append(self.ot_sytem)
                            self.liste.append(self.segment)
                            self.liste.append(self.module)
                            self.liste.append(self.basic_hardware)
                            self.liste.append(self.version)
                            self.liste.append(self.system_name)
                            self.liste.append(self.module_type)
                            self.liste.append(self.serial_number)
                            self.liste.append(self.copyrigthh)

                            if self.ipadress.__len__() >= sayac:
                                print(self.ipadress)
                                for ip in self.ipadress:
                                    print(ip)

                            if self.macadress.__len__() >= sayac:
                                # print(self.liste)
                                n = 17
                                final = [self.liste[i * n:(i + 1) * n] for i in range((len(self.liste) + n - 1) // n)]
                                # print(final)
                                cursor.execute("Select * From sniffer")
                                snifferList = cursor.fetchall()

                                result = []
                                n2 = 18
                                for s in snifferList:
                                    for x in s:
                                        result.append(x)
                                final2 = [result[i * n2:(i + 1) * n2] for i in range((len(result) + n2 - 1) // n2)]
                                print(final2)

                                for l in range(len(final2)):
                                    id_haric = final2[l][1:]
                                    # print(id_haric)
                                    liste_id_haric.append(id_haric)
                                for j in range(final.__len__()):
                                    if liste_id_haric.__len__() == 0:
                                        cursor.execute(
                                            "insert into sniffer(src_macA,src_ipA,vender_namE,type_num,protocol_name,"
                                            "Location,Process,OT_product,OT_system,Segment, module,"
                                            "basic_hardware, version, system_name, module_type, serial_number, copyrigthh)"
                                            " values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                            final[j])
                                        con.commit()
                                    # elif final[j] in final2:
                                    #   break
                                    elif final[j] not in liste_id_haric:
                                        cursor.execute(
                                            "insert into sniffer(src_macA,src_ipA,vender_namE,type_num,protocol_name,"
                                            "Location,Process,OT_product,OT_system,Segment,module,"
                                            "basic_hardware, version, system_name, module_type, serial_number, copyrigthh) "
                                            "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                            final[j])
                                        con.commit()


                        elif self.src_ip in self.ipadress or self.src_mac in self.macadress \
                                or (self.vender_name in self.venderName) or (self.type_name in self.type_array) \
                                or (self.protocol_name in self.protocol_name_array):
                            break
                except:
                    format_exc()


        if 'IP' in raw_packet:
            ip_header = raw_packet['IP']
            if self.type_name == "IPv4":
                self.src_ip = ip_header.src
            else:
                self.src_ip = "-"


        if 'TCP' in raw_packet:
            tcp_header = raw_packet['TCP']
            self.layer_name = tcp_header.layer_name
            self.src_port = int(tcp_header.srcport)
            #print(self.layer_name)
            #print(self.src_port)

            cursor3.execute("Select * From port_protocol")
            port_protocol = cursor3.fetchall()
            result2 = []
            for ss in port_protocol:
                for xx in ss:
                    result2.append(xx)
            n2 = 2
            final3 = [result2[i * n2:(i + 1) * n2] for i in range((len(result2) + n2 - 1) // n2)]
            for j in final3:
                if (self.layer_name == "tcp") and (self.src_port == j[0]):
                    self.protocol_name = j[1]

        if 'MBTCP' in raw_packet:
            pass
        if 'MODBUS' in raw_packet:
            print()
            try:
                modbus_packet = str(raw_packet['MODBUS'])
                parsing_modbus_packet = modbus_packet.split('\n')
                modbus_packet2 = raw_packet['MODBUS']

                self.func_code = modbus_packet2.func_code

            except:
                format_exc()

            try:
                liste_id_haric = []
                sayac = 0
                sayac2 = 0
                while True:
                    if (self.src_ip not in self.ipadress) or (self.src_mac not in self.macadress) \
                    or (self.vender_name not in self.venderName) or (self.type_name not in self.type_array)\
                    or (self.protocol_name not in self.protocol_name_array):

                        #print(self.sayac_olusturma(raw_packet))
                        self.ipadress.append(self.src_ip)
                        for i in range(len(self.ipadress)):
                            sayac = sayac + 1
                            self.sayac3 += 1
                        self.macadress.append(self.src_mac)
                        self.venderName.append(self.vender_name)
                        self.type_array.append(self.type_name)
                        self.protocol_name_array.append(self.protocol_name)
                        #self.id_array.append(self.id)
                        self.location_array.append(self.location)
                        self.process_array.append(self.process)
                        self.ot_product_array.append(self.ot_product)
                        self.ot_sytem_array.append(self.ot_sytem)
                        self.segment_array.append(self.segment)
                        self.module_array.append(self.module)
                        self.basic_hardware_array.append(self.basic_hardware)
                        self.version_array.append(self.version)
                        self.system_name_array.append(self.system_name)
                        self.module_type_array.append(self.module_type)
                        self.serial_number_array.append(self.serial_number)
                        self.copyrigthh_array.append(self.copyrigthh)

                        self.liste.append(self.src_mac)
                        self.liste.append(self.src_ip)
                        self.liste.append(self.vender_name)
                        self.liste.append(self.type_name)
                        self.liste.append(self.protocol_name)
                        self.liste.append(self.location)
                        self.liste.append(self.process)
                        self.liste.append(self.ot_product)
                        self.liste.append(self.ot_sytem)
                        self.liste.append(self.segment)
                        self.liste.append(self.module)
                        self.liste.append(self.basic_hardware)
                        self.liste.append(self.version)
                        self.liste.append(self.system_name)
                        self.liste.append(self.module_type)
                        self.liste.append(self.serial_number)
                        self.liste.append(self.copyrigthh)


                        if self.ipadress.__len__() >= sayac:
                            print(self.ipadress)
                            for ip in self.ipadress:
                                print(ip)

                        if self.macadress.__len__() >= sayac:
                            #print(self.liste)
                            n = 17
                            final = [self.liste[i * n:(i+1) * n] for i in range((len(self.liste)+ n -1) // n)]
                            #print(final)
                            cursor.execute("Select * From sniffer")
                            snifferList = cursor.fetchall()

                            result = []
                            n2 = 18
                            for s in snifferList:
                                for x in s:
                                    result.append(x)
                            final2 = [result[i * n2:(i+1) * n2] for i in range((len(result)+ n2 -1) // n2)]
                            print(final2)
                            for l in range(len(final2)):
                                id_haric = final2[l][1:]
                                #print(id_haric)
                                liste_id_haric.append(id_haric)
                            for j in range(final.__len__()):
                                if liste_id_haric.__len__() == 0:
                                    cursor.execute("insert into sniffer(src_macA,src_ipA,vender_namE,type_num,protocol_name,"
                                                   "Location,Process,OT_product,OT_system,Segment,module,"
                                                    "basic_hardware, version, system_name, module_type, serial_number, copyrigthh)"
                                                   "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", final[j])
                                    con.commit()
                                #elif final[j] in final2:
                                 #   break
                                elif final[j] not in liste_id_haric:
                                    cursor.execute("insert into sniffer(src_macA,src_ipA,vender_namE,type_num,protocol_name,"
                                                   "Location,Process,OT_product,OT_system,Segment,module,"
                                                    "basic_hardware, version, system_name, module_type, serial_number, copyrigthh)"
                                                   " values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", final[j])
                                    con.commit()


                    elif self.src_ip in self.ipadress or self.src_mac in self.macadress \
                    or (self.vender_name in self.venderName) or (self.type_name in self.type_array) \
                    or (self.protocol_name in self.protocol_name_array):
                        break
            except:
                format_exc()

def tablo_olustur():
   cursor.execute("CREATE TABLE IF NOT EXISTS sniffer (id INTEGER PRIMARY KEY AUTOINCREMENT,src_macA TEXT,src_ipA TEXT,vender_namE TEXT, "
                  "type_num TEXT,protocol_name TEXT,Location TEXT,Process TEXT,OT_product TEXT, OT_system TEXT,Segment TEXT, module TEXT,"
                  "basic_hardware TEXT, version TEXT, system_name TEXT, module_type TEXT, serial_number TEXT, copyrigthh TEXT)")

   con.commit()

if __name__ == '__main__':

    parser = PacketParser()
    con = sqlite3.connect("sniffer.db")
    cursor = con.cursor() #veri tababnındaki işlemleri yapmaya yarıyor

    con2 = sqlite3.connect("ether_type.db")
    cursor2 = con2.cursor()

    con3 = sqlite3.connect("port_protocol.db")
    cursor3 = con3.cursor()
    #tablo_olustur()
    try:
        capture = pyshark.LiveCapture(interface='ens33')
        for pkt in capture.sniff_continuously(packet_count=50000):
            parser.packet_parse(pkt)
            #parser.sayac_olusturma(pkt)
        con.close()
        print("bitti")
    except:
        print(format_exc())

