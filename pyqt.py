import os
import sqlite3
from PyQt5 import QtWidgets
import sys
from PyQt5.QtWidgets import *

class Pencere(QMainWindow):
    def __init__(self):
        super().__init__()
        self.baslangic()
        self.sayac2 = 0
        self.sayac4 = 0

    def clickFunc_tara(self):
        os.system("python3 function_code_listen.py")

    def clickFunc_yazdir(self):
        liste = []
        con2 = sqlite3.connect("listen_func_code.db")
        cursor2 = con2.cursor()
        cursor2.execute("Select * From funcCode")
        listen_func_code = cursor2.fetchall()

        for s in listen_func_code:
            for x in s:
                liste.append(x)

        liste2 = []
        with open("func_white_list.rules", "r") as file:
            for i in file:
                i = i[:-1]
                liste2.append(i)

        sayac = 0
        self.table2.setRowCount(len(listen_func_code) + 1)
        self.table2.setColumnCount(2)
        self.table2.setItem(0, 0, QTableWidgetItem("FunctionCode"))
        self.table2.setItem(0, 1, QTableWidgetItem("WhiteList"))
        for i in listen_func_code:
            sayac = sayac + 1
            self.table2.setItem(sayac, 0, QTableWidgetItem(i[0]))
            ch = QtWidgets.QCheckBox(parent=self.table)
            ch.clicked.connect(self.onStateChanged2)
            self.table2.setCellWidget(sayac, 1, ch)

    def onStateChanged2(self):
        con2 = sqlite3.connect("listen_func_code.db")
        cursor2 = con2.cursor()
        cursor2.execute("Select * From funcCode")
        listen_func_code = cursor2.fetchall()
        result = []
        for s in listen_func_code:
            for x in s:
                result.append(x)
        ch = self.sender()
        numara = 0
        numara2 = 0
        new_data = ""

        print(ch.parent())
        ix = self.table2.indexAt(ch.pos())
        if ch.isChecked():
            with open("func_white_list.rules", "a", encoding="utf-8") as file:
                icerik = '{}\n'.format(result[ix.row() - 1])
                file.write(icerik)

        if ch.isChecked() is False:
            with open("func_white_list.rules", "r+", encoding="utf-8") as file2:
                for i in file2:
                    numara += 1
                    if result[ix.row() - 1] in i:
                        numara2 = numara

            with open("func_white_list.rules", "r+", encoding="utf-8") as file3:
                source = file3.read().splitlines()
                for enum, line in enumerate(source, 1):  # enum satır
                    if enum is numara2:  # satır 39 silme 39
                        continue
                    new_data = new_data + line + "\n"

            with open("func_white_list.rules", "w", encoding="utf-8") as file4:
                file4.write(new_data)

    def clickTara(self):
        os.system("python3 packetsniffer.py")

    def clickYazdir(self):
        con = sqlite3.connect("sniffer.db")
        cursor = con.cursor()
        cursor.execute("Select * From sniffer")
        snifferList = cursor.fetchall()

        sayac = 0
        self.table.setRowCount(len(snifferList) + 1)
        self.table.setColumnCount(11)
        self.table.setItem(0, 0, QTableWidgetItem("WhiteList"))
        self.table.setItem(0, 1, QTableWidgetItem("AssetNumber"))
        self.table.setItem(0, 2, QTableWidgetItem("MacAdress"))
        #self.table.setItem(0, 3, QTableWidgetItem("TypeName"))
        self.table.setItem(0, 3, QTableWidgetItem("IpAdress"))
        self.table.setItem(0, 4, QTableWidgetItem("Protocol"))
        self.table.setItem(0, 5, QTableWidgetItem("VenderName"))
        self.table.setItem(0, 6, QTableWidgetItem("Location"))
        self.table.setItem(0, 7, QTableWidgetItem("Process"))
        self.table.setItem(0, 8, QTableWidgetItem("OTProduct"))
        self.table.setItem(0, 9, QTableWidgetItem("OTSystem"))
        self.table.setItem(0, 10, QTableWidgetItem("Segment"))

        for j in snifferList:
            sayac = sayac + 1
            ch = QtWidgets.QCheckBox(parent=self.table)
            ch.clicked.connect(self.onStateChanged)
            self.table.setCellWidget(sayac, 0, ch)
            self.table.setItem(sayac, 1, QTableWidgetItem(str(j[0])))
            self.table.setItem(sayac, 2, QTableWidgetItem(j[1]))
            #self.table.setItem(sayac, 3, QTableWidgetItem(j[4]))
            self.table.setItem(sayac, 3, QTableWidgetItem(j[2]))
            self.table.setItem(sayac, 4, QTableWidgetItem(j[5]))
            self.table.setItem(sayac, 5, QTableWidgetItem(j[3]))
            self.table.setItem(sayac, 6, QTableWidgetItem(j[6]))
            self.table.setItem(sayac, 7, QTableWidgetItem(j[7]))
            self.table.setItem(sayac, 8, QTableWidgetItem(j[8]))
            self.table.setItem(sayac, 9, QTableWidgetItem(j[9]))
            self.table.setItem(sayac, 10, QTableWidgetItem(j[10]))

    def onStateChanged(self):
        con = sqlite3.connect("sniffer.db")
        cursor = con.cursor()
        cursor.execute("Select * From sniffer")
        snifferList = cursor.fetchall()
        ch = self.sender()
        print(ch.parent())
        ix = self.table.indexAt(ch.pos())
        numara = 0
        numara2 = 0
        new_data = ""
        print(ch.checkState())
        print(type(ch.checkState()))
        if ch.isChecked():
            with open("white_list.rules", "a", encoding="utf-8") as file:
                icerik = '{}\n'.format(snifferList[ix.row() - 1][2])
                file.write(icerik)

        if ch.isChecked() is False:
            with open("white_list.rules", "r+", encoding="utf-8") as file2:
                for i in file2:
                    numara += 1
                    if snifferList[ix.row() - 1][2] in i:
                        numara2 = numara

            with open("white_list.rules", "r+", encoding="utf-8") as file3:
                source = file3.read().splitlines()
                for enum, line in enumerate(source, 1):  # enum satır
                    if enum is numara2:  # satır 39 silme 39
                        continue
                    new_data = new_data + line + "\n"

            with open("white_list.rules", "w", encoding="utf-8") as file4:
                file4.write(new_data)

    def clickSnort(self):
        snort_list = []
        home_net = ""
        white_list = "ipvar HOME_NET ["
        with open("white_list.rules", "r", encoding="utf-8") as file:
            for i in file:
                i = i[:-1]
                snort_list.append(i)
        print(snort_list)

        index = 0
        while index < len(snort_list):
            white_list += snort_list[index]
            if index == len(snort_list) - 1:
                white_list += ""
            else:
                white_list += ","
            index = index + 1
        white_list += "]\n"
        print(white_list)

        new_data = ""
        sayac = 0
        sayac3 = 0

        with open("/etc/snort/snort.conf", "r+", encoding="utf8") as sayma:
            for i in sayma:
                i = i[:-1] # /n engellendi
                parsing_snort = i.split('\n')
                #print(parsing_snort)
                sayac = sayac + 1
                for item in parsing_snort:
                    if ('ipvar HOME_NET' in item) and ('#ipvar HOME_NET' not in item) and ('# ipvar HOME_NET' not in item):
                        sayac3 += 1
                        print(sayac3)
                        self.sayac2 = sayac #sayac2 de ipvar home_net in kaçıncı satırda olduğunu soyluyor
                        print(self.sayac2)
                        break

        with open("/etc/snort/snort.conf", "r+", encoding="utf8") as file2:
            source = file2.read().splitlines()
            for enum, line in enumerate(source,1): #enum satır
                if enum is self.sayac2: #satır 39 silme 39
                    continue # sayac2 satırı new data ya atma diyoruz
                new_data = new_data + line + "\n"

        with open("/etc/snort/snort.conf", "w", encoding="utf8") as file3:
            file3.writelines(new_data)

        with open("/etc/snort/snort.conf", "r+", encoding="utf8") as file4:

            liste = file4.readlines()
            #print(self.sayac2)
            liste.insert(self.sayac2 - 1, white_list) #satır 39 ekleme 1 eksiği
            file4.seek(0) #dosyanın basına don sonra bütün hepsini yaz
            for satır in liste:
                file4.write(satır)

    def click_suricata(self):
        suricata_list = []
        white_list = "    HOME_NET: {}".format('"[')
        with open("white_list.rules", "r", encoding="utf-8") as file:
            for i in file:
                i = i[:-1]
                suricata_list.append(i)
        print(suricata_list)

        index = 0
        while index < len(suricata_list):
            white_list += suricata_list[index]
            if index == len(suricata_list) - 1:
                white_list += ""
            else:
                white_list += ","
            index = index + 1
        white_list += ']"\n'
        print(white_list)


        new_data = ""
        sayac = 0
        sayac3 = 0

        with open("/etc/suricata/suricata.yaml", "r+", encoding="utf8") as sayma:
            for i in sayma:
                i = i[:-1]  # /n engellendi
                parsing_snort = i.split('\n')
                # print(parsing_snort)
                sayac = sayac + 1
                for item in parsing_snort:
                    if ('HOME_NET:' in item) and ('#HOME_NET:' not in item) and (
                            '# HOME_NET:' not in item) and ('$HOME_NET' not in item):
                        sayac3 += 1
                        print(sayac3)
                        self.sayac4 = sayac  # sayac2 de ipvar home_net in kaçıncı satırda olduğunu soyluyor
                        print(self.sayac4)
                        break

        with open("/etc/suricata/suricata.yaml", "r+", encoding="utf8") as file2:
            source = file2.read().splitlines()
            for enum, line in enumerate(source, 1):  # enum satır
                if enum is self.sayac4:  # satır 39 silme 39
                    continue  # sayac4 satırı new data ya atma diyoruz
                new_data = new_data + line + "\n"

        with open("/etc/suricata/suricata.yaml", "w", encoding="utf8") as file3:
            file3.writelines(new_data)

        with open("/etc/suricata/suricata.yaml", "r+", encoding="utf8") as file4:

            liste = file4.readlines()
            print(self.sayac4)
            liste.insert(self.sayac4 - 1, white_list)  # satır 39 ekleme 1 eksiği
            file4.seek(0)  # dosyanın basına don sonra bütün hepsini yaz
            for satır in liste:
                file4.write(satır)


    def click_duzenle(self):
        self.SW = SecondWindow()
        self.SW.show()

    def click_detaylar(self):
        self.TW = ThirdWindow()
        self.TW.setGeometry(200, 200, 1500, 1500)
        self.TW.show()

    def click_export_json(self):

        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        # connect to the SQlite databases
        connection = sqlite3.connect("sniffer.db")
        connection.row_factory = dict_factory
        cursor = connection.cursor()

        # select all the tables from the database
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        # for each of the bables , select all the records from the table
        for table_name in tables:
            # table_name = table_name[0]
            print(table_name['name'])

            conn = sqlite3.connect("sniffer.db")
            conn.row_factory = dict_factory

            cur1 = conn.cursor()
            cur1.execute("SELECT * FROM " + table_name['name'])
            # fetch all or one we'll go for all.
            results = cur1.fetchall()
            print(results)
            array = []
            for j in results:
                array.append(str(j))


            with open(table_name['name'] + '.json', 'r') as file:
                cont = file.read()

            # generate and save JSON files with the table name for each of the database tables
            with open(table_name['name'] + '.json', 'r+') as the_file:
                for i in range(0,len(results) + 1):
                    if array[i] not in cont:
                        the_file.writelines("{}\n".format(results[i]).replace(" u'", "'").replace("'", "\""))

        connection.close()

    def baslangic(self):
        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)
        layout = QGridLayout(centralWidget)
        self.table = self.build_table()
        self.table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)  # <---
        # self.tableWidget.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        #self.table = QTableWidget()
        #self.table.setColumnWidth(1, 200)

        self.butonYazdir = QtWidgets.QPushButton("Yazdır")
        self.butonTara = QtWidgets.QPushButton("Taramaya Basla")
        self.butonFunc_tara = QtWidgets.QPushButton("FunctionCode Tara")
        self.buton_duzenle = QtWidgets.QPushButton("Duzenle")
        self.buton_export_json = QtWidgets.QPushButton("Json Formatında Dısa Aktar")
        self.butonFunc_yazdir = QtWidgets.QPushButton("FunctionCode Yazdır")
        self.butonSnort = QtWidgets.QPushButton("Snort Entegrasyonu")
        self.buton_detaylar = QtWidgets.QPushButton("Detayları Göster")
        self.butonSuricata = QtWidgets.QPushButton("Suricata Entegrasyonu")
        self.table2 = QTableWidget()

        self.butonYazdir.clicked.connect(self.clickYazdir)  # butona tıklandığında hangi fonksiyon çalıştığını gösterir
        self.butonTara.clicked.connect(self.clickTara)
        self.butonFunc_tara.clicked.connect(self.clickFunc_tara)
        self.butonFunc_yazdir.clicked.connect(self.clickFunc_yazdir)
        self.butonSnort.clicked.connect(self.clickSnort)
        self.butonSuricata.clicked.connect(self.click_suricata)
        self.buton_duzenle.clicked.connect(self.click_duzenle)
        self.buton_export_json.clicked.connect(self.click_export_json)
        self.buton_detaylar.clicked.connect(self.click_detaylar)

        layout.addWidget(self.butonTara)
        layout.addWidget(self.butonYazdir)
        layout.addWidget(self.butonSnort)
        layout.addWidget(self.butonSuricata)
        layout.addWidget(self.buton_duzenle)
        layout.addWidget(self.buton_export_json)
        layout.addWidget(self.buton_detaylar)
        layout.addWidget(self.table)
        self.show()

    def build_table(self):

        table = QTableWidget()
        con = sqlite3.connect("sniffer.db")
        cursor = con.cursor()
        cursor.execute("Select * From sniffer")
        snifferList = cursor.fetchall()

        sayac = 0
        table.setRowCount(len(snifferList) + 1)
        table.setColumnCount(11)
        table.setItem(0, 0, QTableWidgetItem("WhiteList"))
        table.setItem(0, 1, QTableWidgetItem("AssetNumber"))
        table.setItem(0, 2, QTableWidgetItem("MacAdress"))
        #table.setItem(0, 3, QTableWidgetItem("TypeName"))
        table.setItem(0, 3, QTableWidgetItem("IpAdress"))
        table.setItem(0, 4, QTableWidgetItem("Protocol"))
        table.setItem(0, 5, QTableWidgetItem("VenderName"))
        table.setItem(0, 6, QTableWidgetItem("Location"))
        table.setItem(0, 7, QTableWidgetItem("Process"))
        table.setItem(0, 8, QTableWidgetItem("OTProduct"))
        table.setItem(0, 9, QTableWidgetItem("OTSystem"))
        table.setItem(0, 10, QTableWidgetItem("Segment"))

        for j in snifferList:
            sayac = sayac + 1
            ch = QtWidgets.QCheckBox(parent=table)
            ch.clicked.connect(self.onStateChanged)
            table.setCellWidget(sayac, 0, ch)
            table.setItem(sayac, 1, QTableWidgetItem(str(j[0])))
            table.setItem(sayac, 2, QTableWidgetItem(j[1]))
            #table.setItem(sayac, 3, QTableWidgetItem(j[4]))
            table.setItem(sayac, 3, QTableWidgetItem(j[2]))
            table.setItem(sayac, 4, QTableWidgetItem(j[5]))
            table.setItem(sayac, 5, QTableWidgetItem(j[3]))
            table.setItem(sayac, 6, QTableWidgetItem(j[6]))
            table.setItem(sayac, 7, QTableWidgetItem(j[7]))
            table.setItem(sayac, 8, QTableWidgetItem(j[8]))
            table.setItem(sayac, 9, QTableWidgetItem(j[9]))
            table.setItem(sayac, 10, QTableWidgetItem(j[10]))

        #table.resizeColumnsToContents()
        #table.resizeRowsToContents()
        table.verticalHeader().setVisible(False)
#       self.table.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)         # ---
        return table                                                               # +++

class SecondWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.baslangic()
    def baslangic(self):
        centralWidget = QtWidgets.QWidget()
        self.setCentralWidget(centralWidget)
        layout = QtWidgets.QGridLayout(centralWidget)

        self.label_id = QtWidgets.QLabel("id giriniz ")
        self.label_location = QtWidgets.QLabel("Location giriniz")
        self.label_process = QtWidgets.QLabel("Process giriniz")
        self.label_otProduct = QtWidgets.QLabel("OT Product giriniz")
        self.label_otSystem = QtWidgets.QLabel("OT System giriniz")
        self.label_segment = QtWidgets.QLabel("Segment giriniz")

        self.yazi_alani_id = QtWidgets.QLineEdit()
        self.yazi_alani_location = QtWidgets.QLineEdit()
        self.yazi_alani_process = QtWidgets.QLineEdit()
        self.yazi_alani_otProduct = QtWidgets.QLineEdit()
        self.yazi_alani_otSystem = QtWidgets.QLineEdit()
        self.yazi_alani_segment = QtWidgets.QLineEdit()

        self.buton_gonder = QtWidgets.QPushButton("Veritabanina Gönder")
        self.buton_gonder.clicked.connect(self.click_gonder)

        layout.addWidget(self.label_id)
        layout.addWidget(self.yazi_alani_id)
        layout.addWidget(self.label_location)
        layout.addWidget(self.yazi_alani_location)
        layout.addWidget(self.label_process)
        layout.addWidget(self.yazi_alani_process)
        layout.addWidget(self.label_otProduct)
        layout.addWidget(self.yazi_alani_otProduct)
        layout.addWidget(self.label_otSystem)
        layout.addWidget(self.yazi_alani_otSystem)
        layout.addWidget(self.label_segment)
        layout.addWidget(self.yazi_alani_segment)
        layout.addWidget(self.buton_gonder)

    def click_gonder(self):
        con = sqlite3.connect("sniffer.db")
        cursor = con.cursor()
        cursor.execute("Select * From sniffer")
        id = int(self.yazi_alani_id.text())
        print(id)
        print(type(id))
        location = str(self.yazi_alani_location.text())
        process = str(self.yazi_alani_process.text())
        ot_product = str(self.yazi_alani_otProduct.text())
        ot_system = str(self.yazi_alani_otSystem.text())
        segment = str(self.yazi_alani_segment.text())

        snifferList = cursor.fetchall()
        print(snifferList)
        for j in snifferList:
            print(j[0])
            if id == int(j[0]):
                cursor.execute("Update sniffer set Location = ?,Process = ?, OT_product = ?, OT_system = ?, Segment = ? where id = ?",
                (location, process, ot_product, ot_system, segment, id))
                con.commit()

class ThirdWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.baslangic()
        self.id = 0
    def baslangic(self):
        centralWidget = QtWidgets.QWidget()
        self.setCentralWidget(centralWidget)
        layout = QtWidgets.QGridLayout(centralWidget)

        self.table = QTableWidget()
        self.table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)  # <---
        # self.tableWidget.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.label_id = QtWidgets.QLabel("id giriniz ")
        self.yazi_alani_id = QtWidgets.QLineEdit()
        self.buton_id_gonder = QtWidgets.QPushButton("ID Gönder")

        self.buton_id_gonder.clicked.connect(lambda : self.click_id(int(self.yazi_alani_id.text())))

        layout.addWidget(self.label_id)
        layout.addWidget(self.yazi_alani_id)
        layout.addWidget(self.buton_id_gonder)
        layout.addWidget(self.table)


    def click_id(self,id):
        con = sqlite3.connect("sniffer.db")
        cursor = con.cursor()
        cursor.execute("Select * From sniffer")
        snifferList = cursor.fetchall()

        sayac = 0
        #self.table.setRowCount(len(snifferList) + 1)
        self.table.setRowCount(2)
        self.table.setColumnCount(12)
        #self.table.setItem(0, 0, QTableWidgetItem("WhiteList"))
        self.table.setItem(0, 0, QTableWidgetItem("AssetNumber"))
        self.table.setItem(0, 1, QTableWidgetItem("MacAdress"))
        #self.table.setItem(0, 2, QTableWidgetItem("TypeName"))
        self.table.setItem(0, 2, QTableWidgetItem("IpAdress"))
        self.table.setItem(0, 3, QTableWidgetItem("Protocol"))
        self.table.setItem(0, 4, QTableWidgetItem("VenderName"))
        #self.table.setItem(0, 5, QTableWidgetItem("Location"))
        #self.table.setItem(0, 6, QTableWidgetItem("Process"))
        #self.table.setItem(0, 7, QTableWidgetItem("OTProduct"))
        #self.table.setItem(0, 8, QTableWidgetItem("OTSystem"))
        #self.table.setItem(0, 9, QTableWidgetItem("Segment"))
        self.table.setItem(0, 5, QTableWidgetItem("Module"))
        self.table.setItem(0, 6, QTableWidgetItem("Basic_Hardware"))
        self.table.setItem(0, 7, QTableWidgetItem("Version"))
        self.table.setItem(0, 8, QTableWidgetItem("SystemName"))
        self.table.setItem(0, 9, QTableWidgetItem("ModuleType"))
        self.table.setItem(0, 10, QTableWidgetItem("SerialNumber"))
        self.table.setItem(0, 11, QTableWidgetItem("Copyright"))

        
        for j in snifferList:

            if id == j[0]:
                sayac = sayac + 1
                self.table.setItem(sayac, 0, QTableWidgetItem(str(j[0])))
                self.table.setItem(sayac, 1, QTableWidgetItem(j[1]))
                #self.table.setItem(sayac, 2, QTableWidgetItem(j[4]))
                self.table.setItem(sayac, 2, QTableWidgetItem(j[2]))
                self.table.setItem(sayac, 3, QTableWidgetItem(j[5]))
                self.table.setItem(sayac, 4, QTableWidgetItem(j[3]))
                #self.table.setItem(sayac, 5, QTableWidgetItem(j[6]))
                #self.table.setItem(sayac, 6, QTableWidgetItem(j[7]))
                #self.table.setItem(sayac, 7, QTableWidgetItem(j[8]))
                #self.table.setItem(sayac, 8, QTableWidgetItem(j[9]))
                #self.table.setItem(sayac, 9, QTableWidgetItem(j[10]))
                self.table.setItem(sayac, 5, QTableWidgetItem(j[11]))
                self.table.setItem(sayac, 6, QTableWidgetItem(j[12]))
                self.table.setItem(sayac, 7, QTableWidgetItem(j[13]))
                self.table.setItem(sayac, 8, QTableWidgetItem(j[14]))
                self.table.setItem(sayac, 9, QTableWidgetItem(j[15]))
                self.table.setItem(sayac, 10, QTableWidgetItem(j[16]))
                self.table.setItem(sayac, 11, QTableWidgetItem(j[17]))

app = QtWidgets.QApplication(sys.argv)
pencere = Pencere()
pencere.setGeometry(200,200,1500,1500)
sys.exit(app.exec_())