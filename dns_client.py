import socket
import struct
import time

PACKET_SIZE = 1024

ROOT_DNS_IPS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.9.14.129",
    "199.7.83.42",
    "202.12.27.33"
]

DNS_PORT = 53
HTTP_PORT = 80

DOMAIN_NAME = "httpforever.com"

def construct_dns_packet(domain_name):
    domain = domain_name.split(".")

    id = struct.pack("!H", 12345) # random id 
    flags = struct.pack("!H", 0) 
    q_count = struct.pack("!H", 1)
    ans_count = struct.pack("!H", 0)
    auth_count = struct.pack("!H", 0)
    add_count = struct.pack("!H", 0)

    qname = b''

    for label in domain:
        qname += struct.pack("!B", len(label))
        for c in label:
            qname += struct.pack("!c", c.encode('utf-8'))

    qname += struct.pack("!B", 0)

    qtype = struct.pack("!H", 1)
    qclass = struct.pack("!H", 1)
        

    header = id + flags + q_count + ans_count + auth_count + add_count
    question = qname + qtype + qclass

    packet = header + question

    return packet


def parse_header(packet):

    offset = 4 #skip id and flags

    q_count = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    ans_count = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    auth_count = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    add_count = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    header_counts = dict(qdcount = q_count, ancount = ans_count, nscount = auth_count, arcount = add_count)
    
    print("HEADERS")
    print(header_counts)

    return header_counts, offset

def parse_resource_record(packet, offset):

    # skip name 
    while True:
        label_len = struct.unpack("!B", packet[offset:offset+1])[0]
        
        if (label_len >= 192): # if length is a 2 byte pointer add 2 to offset
            offset +=2
            break

        offset += 1 # account for length byte 

        if (label_len == 0): # if length is 0, no more labels in name
            break
        else:  
            offset += label_len
            
    rtype = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    offset += 6 #skip class and ttl 

    rrdlength = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    rrdata = struct.unpack("!BBBB", packet[offset:offset+4]) #only get as much data as needed for an IPv4 address
    offset += rrdlength

    resource_record = dict(type = rtype, length = rrdlength, data = rrdata)

    return resource_record, offset
    

def parse_question_record(packet, offset):

    # skip name 
    while True:
        label_len = struct.unpack("!B", packet[offset:offset+1])[0]
        offset += 1

        if (label_len == 0):
            break
        else:
            offset += label_len

    qtype = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    qclass = struct.unpack("!H", packet[offset:offset+2])[0]
    offset += 2

    question_record = dict(type = qtype, qclass = qclass)

    return question_record, offset


def parse_dns_response(packet):
 
    header_counts, offset = parse_header(packet)

    q_count = header_counts["qdcount"]
    ans_count = header_counts["ancount"]
    auth_count = header_counts["nscount"]
    add_count = header_counts["arcount"]

    question_records = []
    answer_records = []
    authority_records = []
    additional_records = []

    valid_ips = []

    print("QUESTION RECORDS")
    if q_count == 0:
        print("None")
    else:
        for i in range(q_count):
            question_record, offset = parse_question_record(packet, offset)
            question_records.append(question_record)
            print(f"{i+1} -- {question_record}")

    print("ANSWER RECORDS")
    if ans_count == 0:
        print("None")
    else:
        for i in range(ans_count):
            answer_record, offset = parse_resource_record(packet, offset)
            answer_records.append(answer_record)
            print(f"{i+1} -- {answer_record}")

            if answer_record.get("type") == 1:
                ip = ".".join(map(str, answer_record.get("data")))
                valid_ips.append(ip)

    print("AUTHORITY RECORDS")
    if auth_count == 0:
        print("None")
    else:
        for i in range(auth_count):
            authority_record, offset = parse_resource_record(packet, offset)
            authority_records.append(authority_record)
            print(f"{i+1} -- {authority_record}")

            if authority_record.get("type") == 1:
                ip = ".".join(map(str, authority_record.get("data")))
                valid_ips.append(ip)

    print("ADDITIONAL RECORDS")
    if add_count == 0:
        print("None")
    else:
        for i in range(add_count):
            additional_record, offset = parse_resource_record(packet, offset)
            additional_records.append(additional_record)
            print(f"{i+1} -- {additional_record}")

            if additional_record.get("type") == 1:
                ip = ".".join(map(str, additional_record.get("data")))
                valid_ips.append(ip)

    print("VALID IPS")
    print(valid_ips)
    print("----------------------------------------------------------------------------------------")
    return valid_ips


local_ips = []

print(f"Querying for domain {DOMAIN_NAME}")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:


    packet = construct_dns_packet(DOMAIN_NAME)

    tld_ips = []
    ack = b''

    for ip in ROOT_DNS_IPS:
        try:
            print(f"Attempting to send packet to Root DNS Server: {ip}")
            udp_socket.settimeout(20)

            root_start_time = time.time()
            udp_socket.sendto(packet, (ip, DNS_PORT))

            ack, _ = udp_socket.recvfrom(PACKET_SIZE)
            root_end_time = time.time()
            print("Response received.")
            print(f"Measured RTT to Root DNS server: {root_end_time - root_start_time}")
            tld_ips = parse_dns_response(ack)
            udp_socket.settimeout(None)
            break
            
            

        except socket.timeout:
            print(f"Query timed out.")
            continue

    authoritative_ips = []

    for ip in tld_ips:
        try:
            print(f"Attempting to send packet to TLD DNS Server: {ip}")
            udp_socket.settimeout(20)

            tld_start_time = time.time()
            udp_socket.sendto(packet, (ip, DNS_PORT))

            ack, _ = udp_socket.recvfrom(PACKET_SIZE)
            tld_end_time = time.time()
            print("Response received.")
            print(f"Measured RTT to TLD DNS server: {tld_end_time - tld_start_time}")
            authoritative_ips = parse_dns_response(ack)
            udp_socket.settimeout(None)
            break

        except socket.timeout:
            print(f"Query timed out.")
            continue

    for ip in authoritative_ips:
        try:
            print(f"Attempting to send packet to authoritative DNS Server: {ip}")
            udp_socket.settimeout(20)

            auth_start_time = time.time()
            udp_socket.sendto(packet, (ip, DNS_PORT))

            ack, _ = udp_socket.recvfrom(PACKET_SIZE)
            auth_end_time = time.time()
            print("Response received.")
            print(f"Measured RTT to authoritative DNS server: {auth_end_time - auth_start_time}")
            local_ips = parse_dns_response(ack)
            udp_socket.settimeout(None)
            break

        except socket.timeout:
            print(f"Query timed out.")
            continue
    
tcp_socket = None
response = b''
for ip in local_ips:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        tcp_socket.connect((ip, HTTP_PORT))
        http = f'GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n'
        http_packet = http.encode()
        print(f"Sending HTTP GET request to IP: {ip}")

        http_start_time = time.time()
        tcp_socket.sendall(http_packet)

        http_end_time = 0
        while True:
            try:
                tcp_socket.settimeout(5)
                response += tcp_socket.recv(PACKET_SIZE)
                tcp_socket.settimeout(None)
            except socket.timeout:
                http_end_time = time.time()
                tcp_socket.close()
                tcp_socket = None
                break

        if (response == b''):
            continue
        else:
            print(f"Measured RTT to tmz.com server: {http_end_time - http_start_time - 5}")
            break

f = open('./tmz.html', 'wb')
f.write(response)
f.close()
print("HTTP response saved to tmz.html")

    