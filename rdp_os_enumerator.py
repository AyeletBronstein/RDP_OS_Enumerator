#research pentera
#rdp_os_enumerator

import socket
import struct
import ssl
from collections import namedtuple

os_dict={"3.1.511":"Windows NT 3.1",
"3.5.807":"Windows NT 3.5",
"3.1.528":"Windows NT 3.1, Service Pack 3",
"3.51.1057":"Windows NT 3.51",
"4.950":"Windows 95",
"4.950 A":"Windows 95 OEM Service Release 1",
"4.950 B":"Windows 95 OEM Service Release 2",
"4.1381":"Windows NT 4.0",
"4.950 B":"Windows 95 OEM Service Release 2.1",
"4.950 C":"Windows 95 OEM Service Release 2.5",
"4.1.1998":"Windows 98",
"4.1.2222":"Windows 98 Second Edition (SE)",
"5.2195":"Windows 2000",
"4.9.3000":"Windows Me",
"5.1.2600":"Windows XP",
"5.1.2600.1105-1106":"Windows XP, Service Pack 1",
"5.2.3790":"Windows Server 2003",
"5.1.2600.218":"Windows XP, Service Pack 2",
"5.2.3790.118":"Windows Server 2003, Service Pack 1",
"5.2.3790":"Windows Server 2003 R2",
"6.6000":"Windows Vista",
"5.2.3790":"Windows Server 2003, Service Pack 2",
"5.2.4500":"Windows Home Server",
"6.6001":("Windows Vista, Service Pack 1","Windows Server 2008"),
"5.1.2600":"Windows XP, Service Pack 3",
"6.6002":("Windows Vista, Service Pack 2", "Windows Server 2008, Service Pack 2"),
"6.1.7600":("Windows 7","Windows Server 2008 R2"),
"6.1.7601":("Windows 7, Service Pack 1","Windows Server 2008 R2, Service Pack 1"),
"6.1.8400":"Windows Home Server 2011",
"6.2.9200":("Windows Server 2012","Windows 8"),
"6.3.9600":("Windows 8.1","Windows Server 2012 R2"),
"10.10240":"Windows 10, Version 1507",
"10.10586":"Windows 10, Version 1511",
"10.14393":("Windows 10, Version 1607","Windows Server 2016, Version 1607"),
"10.15063":"Windows 10, Version 1703",
"10.16299":("Windows 10, Version 1709","Windows Server 2016, Version 1709"),
"10.17134":"Windows 10, Version 1803",
"10.17763":("Windows Server 2019, Version 1809","Windows 10, Version 1809"),
"6.6003":"Windows Server 2008, Service Pack 2, Rollup KB4489887",
"10.18362":"Windows 10, Version 1903",
"10.18363":"Windows 10, Version 1909",
"10.19041":"Windows 10, Version 2004",
"10.19042":"Windows 10, Version 20H2"}


#test_ip = "34.145.84.117"
test_ip = "69.46.9.134"

Signature = "\x30\x37\xa0\x03\x02\x01\x60\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04\x28"
Identifier  = "\x4e\x54\x4c\x4d\x53\x53\x50\x00" #NTLMSSP
Type= "\x01\x00\x00\x00" #NTLMSSP Negotiate
Flags = "\xb7\x82\x08\xe2" #(NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
DomainNameLen = "\x00\x00"
DomainNameMaxLen = "\x00\x00"
DomainNameBufferOffset = "\x00\x00\x00\x00"
WorkstationLen = "\x00\x00"
WorkstationMaxLen = "\x00\x00"
WorkstationBufferOffset = "\x00\x00\x00\x00"
ProductMajorVersion  = "\x0a"
ProductMinorVersion = "\x00"
ProductBuild = "\x63\x45"
Reserved = "\x00\x00\x00"
NTLMRevision = "\x0f" #NTLMSSP_REVISION_W2K3)

#specific ntml handshake params
NTLM_NEG = Signature + Identifier + Type + Flags + DomainNameLen + DomainNameMaxLen + DomainNameBufferOffset + WorkstationLen + WorkstationMaxLen + WorkstationBufferOffset + ProductMajorVersion + ProductMinorVersion + ProductBuild + Reserved + NTLMRevision
 
unwrapped_rdp_connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #tcp/ipv4 socket
unwrapped_rdp_connection_socket.settimeout(60)

rdp_connection_socket = ssl.wrap_socket(unwrapped_rdp_connection_socket) # wrap ssl

rdp_connection_socket.connect((test_ip, 3389))
rdp_connection_socket.send(NTLM_NEG)

server_response = rdp_connection_socket.recv(4096)

start_index = server_response.index("NTLMSSP") #if not in - exception

Parsed_Header = namedtuple("Parsed_Header", "identifier, message_type, domain_length, domain_max, domain_offset, server_flags, challenge")
#Parsed_Target_Realm = namedtuple()
Parsed_Target_Info = namedtuple("Parsed_Target_Info", "context, target_info_length, target_info_max, target_info_offset")
Parsed_Build = namedtuple("Parsed_Build", "major, minor, build, reserved")

psb = Parsed_Header._make(struct.unpack("<7sxI HHI IQ", server_response[start_index:start_index+32]))

print("parsed header:",psb)

#just for dubug perpose ERASE BEFORE GIVE IN
if psb.identifier != "NTLMSSP":
	print("unexpected identifier in response")
	raise(Exception("unexpected identifier in response. exception NTLMSSP"))

if psb.message_type != 2:
	print("unexpected message_type in response")
	raise(Exception("unexpected message_type in response. expecting message_type 2"))
	
target_realm = struct.unpack("<{0}s".format(psb.domain_length),server_response[psb.domain_offset:psb.domain_offset+psb.domain_length])
print ("target_realm:",target_realm)


pti = Parsed_Target_Info._make(struct.unpack("<Q HHI", server_response[start_index+32:start_index+48]))
ps = Parsed_Build._make(struct.unpack("<BBH4s", server_response[start_index+48:start_index+56]))
print("target info:",pti)
print(ps)
target_info= struct.unpack("<{0}s".format(pti.target_info_length),server_response[pti.target_info_offset:pti.target_info_offset + pti.target_info_length])
print ("target_info:",target_info)

product_ver = str(ps.major)+"."+str(ps.minor)+"."+str(ps.build)
print(os_dict[product_ver])

rdp_connection_socket.close()


