'''
@Requirement: pyshark
'''

import csv
import pyshark
from traceback import format_exc


class PacketParser:
    def __init__(self):
        self.pretty_format = []
        self.packet_number = 0
        self.isFirstPacket = True
        self.initial_state()

    def initial_state(self):
        self.protocol = 0
        self.src_ip = ""
        self.dst_ip = ""
        self.func_code = 0
        self.word_cnt = 0
        self.reg_num = 0
        self.isModbus = False


    def packet_parse(self, raw_packet):
        self.initial_state()

        if self.isFirstPacket:
            self.timestamp = float(raw_packet.sniff_timestamp[:15])
            self.prev_timestamp = self.timestamp
            self.packet_number = 1
            self.isFirstPacket = False
        else:
            self.packet_number += 1
            now_timestamp = raw_packet.sniff_timestamp[:15]
            self.timestamp = float(str(float(now_timestamp) - float(self.prev_timestamp))[:10])
            self.prev_timestamp = float(now_timestamp)


        if 'IP' in raw_packet:
            ip_header = raw_packet['IP']
            self.src_ip = ip_header.src
            self.dst_ip = ip_header.dst


        if 'MODBUS' in raw_packet:
            try:
                self.isModbus = True
                modbus_packet = raw_packet['MODBUS']
                self.reg_num = modbus_packet.regnum16
                print(self.reg_num)
                self.protocol = 'Modbus'
                self.word_cnt = modbus_packet.word_cnt
                self.func_code = modbus_packet.func_code
            except:
                format_exc()


        if self.isModbus:
            self.isModbus = False
            pretty_format.append(
                {"packet_number": self.packet_number, "timestamp": self.timestamp, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
                 "protocol": self.protocol, "reg_num": self.reg_num })

    def write_to_csv(self, json_data, filename):
        try:
            filename_format = "{}.csv".format(filename)
            csv_file = open(filename_format, 'w')
            csvwriter = csv.writer(csv_file)
            # str_json_data = json.loads(json_data)
            count = 0

            for data in json_data:
                if count == 0:
                    header = data.keys()
                    csvwriter.writerow(header)
                    count += 1

                csvwriter.writerow(data.values())

            csv_file.close()
            print("Parsed csv created successfully")
        except:
            print(format_exc())


if __name__ == '__main__':
    pretty_format = list()
    parser = PacketParser()
    try:
        capture = pyshark.LiveCapture(interface='ens33')
        for pkt in capture.sniff_continuously(packet_count=500):
            parser.packet_parse(pkt)
        print(pretty_format)
        parser.write_to_csv(pretty_format, "modbus")
    except:
        print(format_exc())
