#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# dictionary: MAC - port
mac_table = {}
# dictionary: port - VLAN/T
ports = {}
# dictionary: port - state
# blocking - 0 ; listening - 1
ports_states = {}

own_bridge_ID = 0
root_bridge_ID = 0
sender_bridge_ID = 0
root_path_cost = 0
sender_path_cost = 0
root_port = -1
BDPU_MAC = b'\x01\x80\xC2\x00\x00\x00'

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    global root_bridge_ID, own_bridge_ID
    while True:
        # TODO Send BDPU every second if necessary
        # daca sunt in root switch
        if root_bridge_ID == own_bridge_ID:
            for port in ports:
                # daca e port Trunk
                if int(ports[port]) == 0:
                    root_bridge_ID = own_bridge_ID
                    sender_bridge_ID = own_bridge_ID
                    sender_path_cost = 0
                    D_MAC = b'\x01\x80\xC2\x00\x00\x00'
                    S_MAC = get_switch_mac()
                    LLC_LENGTH =  b'\x11\x00'
                    LLC_HEADER = b'\x42\x42\x03'
                    v1 = struct.pack("!I", root_bridge_ID)
                    v2 = struct.pack("!I", own_bridge_ID)
                    v3 = struct.pack("!I", root_path_cost)
                    v4 = struct.pack("!B", port)
                    BDPU_CONFIG = v1 + v2 + v3 + v4
                    BDPU_FRAME = D_MAC + S_MAC + LLC_LENGTH + LLC_HEADER + BDPU_CONFIG
                    send_to_link(port, len(BDPU_FRAME), BDPU_FRAME)
        time.sleep(1)

def main():
    global own_bridge_ID, root_bridge_ID, sender_bridge_ID, root_path_cost, sender_path_cost, root_port
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    file = "configs/switch{}.cfg".format(switch_id)

    # open file as config
    with open(file, "r") as fisier:
        config = fisier.readlines()
    for line in config:
        print("line", line)

    # salvez pentru fiecare interfata VLAN-ul sau 0 pentru Trunk
    for i in interfaces:
        for line in config:
            if line.startswith(get_interface_name(i)):
                # daca e de tip Trunk salvez ca "T"
                if line.count("T") == 1:
                    ports[i] = "0"
                else:
                    # daca e de tip Access salvez VLANUL
                    ports[i] = line[4]

    # setez Blocking si Listening pentru fiecare port
    for i in interfaces:
        # daca e port Trunk
        if int(ports[i]) == 0:
            ports_states[i] = 0
        # daca e port Access
        else:
            ports_states[i] = 1

    own_bridge_ID = int(config[0])
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    # daca portul devine root setam porturile ca designated
    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            ports_states[i] = 1

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()
    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()
        if data[:6] == BDPU_MAC:
            BDPU_CONFIG = data[17:]  
            # BDPU root_bridge_id own_bridge_id root_path_cost port_id;  
            v1, v2, v3, v4 = struct.unpack("!III B", BDPU_CONFIG)
            if int(v1) < int(root_bridge_ID):
                root_bridge_ID = v1
                root_path_cost = v3 + 10
                root_port = interface
                for port in ports:
                    if port != root_port and int(ports[port]) == 0:
                        ports_states[port] = 0
                ports_states[root_port] = 1
                # update si forward BDPU
                for port in ports:
                    if port != root_port and int(ports[port]) == 0:
                        updated_BDPU = struct.pack("!III B", root_bridge_ID, own_bridge_ID, root_path_cost, port)
                        BDPU_FRAME = BDPU_MAC + get_switch_mac() + b'\x11\x00' + b'\x42\x42\x03' + updated_BDPU
                        send_to_link(port, len(BDPU_FRAME), BDPU_FRAME)
            elif int(v1) == int(root_bridge_ID):
                if interface == root_port:
                    if v3 + 10 < root_path_cost:
                        root_path_cost = v3 + 10
                else:
                    if v3 > root_path_cost:
                        ports_states[interface] = 1
                    else:
                        ports_states[interface] = 0
            if int(own_bridge_ID) == int(root_bridge_ID):
                for port in ports:
                    ports_states[port] = 1

        # daca nu e BDPU
        else:
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            # Print the MAC src and MAC dst in human readable format
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            # Note. Adding a VLAN tag can be as easy as
            # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

            print(f'Destination MAC: {dest_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, interface), flush=True)

            # TODO: Implement forwarding with learning
            # TODO: Implement VLAN support
            # TODO: Implement STP support

            # data is of type bytes.
            # send_to_link(i, length, data)

            # add MAC and interface to MAC table
            mac_table[src_mac] = interface
        
            vlan = 0
            trunk = 0
            # verific pe ce interfata am primit cadrul si salvez vlan-ul        
            vlan = int(ports[interface])
            # daca vine de pe o interfata Trunk
            if vlan == 0:
                trunk = 1
                vlan = vlan_id

            # verific daca MAC e in mac_table 
            if dest_mac in mac_table:
            # unicast
                # daca portul pe care vreau sa trimit e listening
                if ports_states[mac_table[dest_mac]] == 1:
                # daca trimit pe un port Trunk
                    if int(ports[mac_table[dest_mac]]) == 0:
                        # daca trimit pe un port Trunk de pe un port Trunk
                        if trunk == 1:
                            send_to_link(mac_table[dest_mac], length, data)
                        # daca trimit pe un port Trunk de pe un port Access
                        else:
                            # adaug headerul 802.1Q
                            tag = create_vlan_tag(vlan)
                            frame = data[:12] + tag + data[12:]
                            send_to_link(mac_table[dest_mac], length + 4, frame)

                    # daca trimit pe un port Access
                    else:
                        # daca trimit pe un port Access de pe un port Trunk
                        if trunk == 1:
                            # verific daca portul Access are acelasi VLAN
                            if int(ports[mac_table[dest_mac]]) == vlan_id:
                                # scot headerul 802.1Q
                                frame = data[:12] + data[16:]
                                send_to_link(mac_table[dest_mac], length - 4, frame)
                        # daca trimit pe un port Access de pe un port Access
                        else:
                            # verific daca portul Access are acelasi VLAN
                            if int(ports[mac_table[dest_mac]]) == vlan:
                                send_to_link(mac_table[dest_mac], length, data)
            
            # broadcast
            else:
                for i in interfaces:
                    if i != interface:
                        # daca portul pe care vreau sa trimit este listening
                        if ports_states[i] == 1:
                            # lfl ca la unicast doar ca nu mai folosesc mac_table
                            # daca trimit pe un port Trunk
                            if int(ports[i]) == 0:
                                # daca trimit pe un port Trunk de pe un port Trunk
                                if trunk == 1:
                                    send_to_link(i, length, data)
                                # daca trimit pe un port Trunk de pe un port Access
                                else:
                                    # adaug headerul 802.1Q
                                    tag = create_vlan_tag(vlan)
                                    frame = data[:12] + tag + data[12:]
                                    send_to_link(i, length + 4, frame)

                            # daca trimit pe un port Access
                            else:
                                # daca trimit pe un port Access de pe un port Trunk
                                if trunk == 1:
                                    # verific daca portul Access are acelasi VLAN
                                    if int(ports[i]) == vlan_id:
                                        # scot headerul 802.1Q
                                        frame = data[:12] + data[16:]
                                        send_to_link(i, length - 4, frame)
                                # daca trimit pe un port Access de pe un port Access
                                else:
                                    # verific daca portul Access are acelasi VLAN
                                    if int(ports[i]) == vlan:
                                        send_to_link(i, length, data)


if __name__ == "__main__":
    main()
