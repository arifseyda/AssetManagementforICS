# Asset Management for ICS

This asset management tool was developed in the National Testbed Center project (Center SAU - https://center.sakarya.edu.tr). The developed software has been tested in this test bed center. 

Python pyshark library, which uses tshark infrastructure, is used to listen to the network. The pyqt library was used to create the visualization. 

In this asset management tool, 3 different methods are used to discover and make sense of assets. These methods are passive listening, active querying and making sense of metadata information. 

# Passive Listening 

In industrial control systems, passive monitoring is to enable analysis of network traffic by listening to Tap devices. With the help of the analyzed traffic tshark, the data was parsed with the Pyshark library in the Python programming language. The parsed data are taken as mac addresses, ip addresses, protocol names and vendor names as in the image below. The asset number is the id number created in the database. This id number increases automatically. 

![image](https://user-images.githubusercontent.com/47140243/155843390-a6927ef2-7ef0-4d66-b4a5-99bc05c51a14.png)

When we click the "Taramaya Basla (start scanning)" button, packetsniffer.py is running. In Packetsniffer.py, there is a separate if block for Ethernet, a separate if block for Ip, and a separate if block for TCP.

It is the conversion of the data from the Tap device into an Ethernet frame in the Ethernet if block. It is said to parse the mac address part from the Ethernet framework. Thanks to this mac address, the vendor's name of the product also appears. The vendor provides the first 24 bits of the Mac address. This mac address has been found by the vendor name with the help of an API. 

The data field of the Ethernet frame is taken in the if block created for Ip. The thread head included in the thread package is ready to be parsed. The ip address part is taken in the ip header.

The data field in the Ip packet is taken in the if block created for TCP. The TCP header in the TCP segment is ready to be parsed. The port number field is parsed from the TCP header. The port number from the system is sent to the database we created, which contains the port number and the protocol name. As a result of this sent port number, the protocol name is returned.

A string has been created to send mac addresses, vendor names, ip addresses and protocol names to the database. This sequence is controlled. If there is the same ip address and mac address data in this array, it is called adding to the array again. The data added to each array forms the column of a row in the database. 

With the "Taramaya Basla (Start Scan)" button, 500 packets are listened. After 500 packets, the packet listening process ends. When we click the "Yazdır (Print)" button, if a new device in the system is discovered or a new data is added to the database, it allows us to see it on the form screen. 

# Active Probing

In industrial control systems, active query is made in order to get more information about the system and to analyze the system better due to the inadequacy of the data coming from the active query and passive monitoring. Since it sends a query to the system, a query should not always be sent. A query is sent at regular intervals and what is going on in the system is understood with the help of the data formed as a result of the query. 

Nse scripts are used for active query. There are protocol-based nse scripts to get more information on the protocols. Protocols such as Modbus, DNP3 have nse scripts. There are also nse scripts to get more information on the products. For example, there are nse scripts that check whether Siemens devices have HMI-miniweb feature or WINCC feature. 

In the project we want to develop, both protocol-based and product-based nse scripts were run. Due to the fact that the reliability of the product is more important than the low version level, some outputs either did not yield any results on some devices, or even though we sent the same query, less information was returned because the version level was high.

For example, s7-info is an nse script used to get information inside Siemens S7 devices. Since the version number is 2.6.0, that is low, a lot of information can be returned. However, in devices with higher version number, Module, Basic Hardware and version part return as the answer of the query. 


![image](https://user-images.githubusercontent.com/47140243/155843565-b53cd6b7-cf8c-4720-b702-73a2a9b11b6c.png)

The answers returned from the active query are usually put in the details section in large companies. In the project we want to develop, when the "Detayları Göster (Show Details)" button in the image below is pressed, the answers appear if an active query has been made. 

![image](https://user-images.githubusercontent.com/47140243/155843613-0c32e6bd-0498-40f0-a560-cbd6b5ae39d9.png)

When the "Detayları Göster (Show Details)" button is pressed, a new form appears. When we enter the id (asset number) in this form, we see more detailed, that is, active query results. 

![image](https://user-images.githubusercontent.com/47140243/155843637-e8609db6-46d8-4b91-8872-b433e69852ec.png)

The results of nse scripts are parsed in packetsniffer.py. Incoming IP addresses are used in the nse script. With the help of Python's subprocess library, scripts running in the terminal also work in code. The results that appear on the console screen in the terminal are returned as a tuple in the code. The name is parsed according to the importance of the data. In other words, when you see the Module, it is said to get the next query answer from the Module. 


# Making sense of Metadata information 

If an attacker learns the ip address of one of the entities in your network and you make that ip address his own ip address, it is understood which one is the real entity on the network with the help of metedata information. For example, if we enter the parts such as which project is using this asset or in which location it is located as metedata information, we will avoid the duplicated IP addresses. 

In the system we want to develop, as in the image below, the Location, process, OT product, OT system and Segment sections are empty at first. 

![image](https://user-images.githubusercontent.com/47140243/155843958-d9bc7045-3065-4aba-aba5-cb400a2d9e83.png)

If we want to add to this data, you need to click on the "Duzenle (Edit)" button. 

![image](https://user-images.githubusercontent.com/47140243/155843974-e732dd73-117f-457d-818b-33e21b725f5f.png)

When we click the "Yazdır (Print)" button after entering the data, the data returned from the "Duzenle (Edit)" section appear as follows. 

![image](https://user-images.githubusercontent.com/47140243/155844007-e1380570-6d74-4d47-b6f8-540ea19c11c4.png)

In order to perform these operations, data such as location and process are assigned to the database in packetsniffer.py. In the data entered in the "Duzenle (Edit)" button, the database is updated according to the id. In this way, we can see the new data when we click the "Yazdır (Print)" button. 

# The other features of asset management tool 


# Intrusion Detection System Based on Asset Management 

When we select each of the checkboxes in the whitelist section in the image below, it is written to the white_list.rules file. When a selected checkbox on the whitelist line is pressed again, the tick is removed and the ip address on the checkbox line in white_list.rules is removed from the file. 

The 5 selected IP addresses are written to Whitelist.rules as seen below. 

![image](https://user-images.githubusercontent.com/47140243/155844219-472f88c6-86f9-4510-924d-e80e2e6f979c.png)


Saying Snort and Suricata Integration, these ip addresses are written in /etc/snort/snort.conf and /etc/suricata/suricata.yaml files. These configuration files are already essential for Snort and Suricata to work. 

![image](https://user-images.githubusercontent.com/47140243/155844234-2048dcc3-4a2b-45c0-a7d6-666f19f24c80.png)

In the image below, tmux is used. It helps us to see a terminal as a page at once. I was asked to show the configuration file of Snort and Suricata IDS at the same time. 

![image](https://user-images.githubusercontent.com/47140243/155844243-d67f531f-0800-43ab-9105-4b22046dfaff.png)

It is seen that the ip addresses in White_list.rules are written to the Snort.conf and Suricata.yaml files. 

![image](https://user-images.githubusercontent.com/47140243/155844255-753036cd-2d70-45d5-b6fc-f8aef7b462ea.png)

In order to be able to do these operations, when the checkbox is selected, that line goes to a function. In this function, the ip address of the checkbox selected line is taken. If this ip address is not in the written file, it is called write to the file. 

In Snort and Suricata Integration, the HOME_NET fields are different. According to them, the ip addresses in the file that writes the HOME_NET fields ip addresses are assigned to a string. It is said to find the HOME_NET line in the conf file of Snort IDS and in the yaml file of Suricata IDS, delete the HOME_NET I in that line and replace it with the HOME_NET string containing the ip addresses in the white_list.rules file we created. 

In Snort and Suricata IDS, the assets we want to protect were written in the HOME_NET field. We can detect attacks by running Snort and Suricata IDS. We can send the created log files to the log management tools. 

# Export Json format

When we click the "Json formatında dışa aktar (export in json format)" button, the information in the database is written to the sniffer.json file as json. This sniffer.json file can be visualized in Kibana. While monitoring in Kibana, the IP addresses in your own system are known. If different ip addresses come from these ip addresses, it can be understood that an attack can be made. 

![image](https://user-images.githubusercontent.com/47140243/155844050-5f9206f0-44aa-4513-a7a4-3d532b9e3b85.png)

A dashboard screen with ip addresses, mac addresses, vendor names and protocol information has been created in Kibana. This dashboard part consists of data in sniffer.json. 

![image](https://user-images.githubusercontent.com/47140243/155855002-31cd5a06-76f6-4737-a3a4-8e07bc43bd76.png)


