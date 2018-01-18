from dns.exception import DNSException
from dns import reversename
from dns import resolver
import subprocess
import os.path
import pycurl
import socket
import sys
import io

# WIP - add ping feature, XLSX integration, multithreading
# Ideas to solve current bugs
# -make sure front starts with http
# -if string contains http then start substring until string startswith http
# -if string does not contain http then append the host ip

print("\n***   This script is for performing reverse-lookup & getting redirected URL   ***\n")
print("\nNOTE: File will create 2 output file - 1 for redirected URL, 1 for reverse-lookup hostnames\n\n")


ifs = input("Enter input filename (input.txt) -> ")
#process the ifs, remove postfix extension, get filename
if ifs.endswith('.txt'):
    filename = ifs[:-4]
#ofs1 = file that outputs reverse lookup
#ofs2 = file that outputs redirected URL
ofs1 = filename + "_reverse_hostname.txt"
ofs2 = filename + "_redirected_URL.txt"
if os.path.isfile(ofs1):
    os.remove(ofs1)
    print("Removed " + ofs1)
if os.path.isfile(ofs2):
    os.remove(ofs2)
    print("Removed " + ofs2)

ins = open(ifs, "r")

list_of_ip = []
ptr_output_list = []
curl_output_list = []


print("Reading list of IP Addresses ...")

#open both output file first

ptr_outs = open(ofs1, 'w')
curl_outs = open(ofs2, 'w')

#process each line of entry in the input file
for line in ins:
    list_of_ip.append(line.replace('\n',''))

print("Done reading list of IP Addresses.")
ins.close()

for s in list_of_ip:
    print("\nProcessing IP : " + s)
    try:
        addr = reversename.from_address(s)
        resolver.timeout = 1.0
        resolver.lifetime = 1.0
        resolved_addr = ""

        query_result = resolver.query(addr, "PTR")

        if len(query_result) == 0:
            resolved_addr = str(query_result[0])[:-1]
        else:
            for i in range(0, len(query_result)):
                resolved_addr += str(query_result[i])[:-1] + ", "
            resolved_addr = resolved_addr[:-2]

        print("[PTR] Resolved address: " + resolved_addr)
        print(resolved_addr,file=ptr_outs)
    except (resolver.NXDOMAIN, DNSException, resolver.YXDOMAIN) as e:
        #this is where you want to scan for port 80 / 443
        #if port active, print http://<ip_addr> or https://<ip_addr>
        remoteServerIP = socket.gethostbyname(s)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #customize your timeout here. time is in second(s)
            sock.settimeout(10)
            print("[PTR] Checking HTTPS port ...")
            result = sock.connect_ex((remoteServerIP, 443))
            if result == 0:
                print("[PTR] Resolved address: https://" + s)
                print("https://" + s, file=ptr_outs)
            else:
                #clear result first
                print("[PTR] HTTPS port closed. Checking HTTP port")
                result = None
                result = sock.connect_ex((remoteServerIP, 80))
                if result == 0:
                    print("[PTR] Resolved address: http://" + s)
                    print("http://" + s, file=ptr_outs)
                else:
                    #try to scan for open ftp port
                    print("[PTR] HTTP port closed. Checking FTP port")
                    result = None
                    result = sock.connect_ex((remoteServerIP, 21))
                    if result == 0:
                        print("[PTR] Resolved address: ftp://"+s)
                        print("ftp://" + s, file=ptr_outs)
                    else:
                        #try to scan for open ssh port
                        print("[PTR] FTP port closed. Checking SSH port")
                        result = None
                        result = sock.connect_ex((remoteServerIP, 22))
                        if result == 0:
                            print("[PTR] Resolved address: ssh://"+s)
                            print("ssh://" + s, file=ptr_outs)
                        else:
                            print("[PTR] SSH port closed. IP / Domain inactive")
                            print("No such domain", file=ptr_outs)
        except socket.gaierror:
            print("[PTR] Hostname could not be resolved.")
            print("No such domain", file=ptr_outs)
        except socket.error:
            print("[PTR] Couldn't connect to server")
            print("No such domain", file=ptr_outs)
    except resolver.Timeout:
        print("[PTR] Timed out while resolving")
        print("No such domain", file=ptr_outs)
    except resolver.DNSException:
        print("[PTR] Unhandled exception")
        print("No such domain", file=ptr_outs)

    #PTR operation done. moving on to do curl operation

    try:
        print("[CURL] Processing http://" + s)

        o = io.BytesIO()
        h = io.BytesIO()

        c = pycurl.Curl()
        host = s
        c.setopt(c.URL, host)
        c.setopt(c.WRITEFUNCTION, o.write)
        c.setopt(c.HEADERFUNCTION, h.write)
        c.setopt(c.CONNECTTIMEOUT, 30)
        c.setopt(c.AUTOREFERER,1)
        c.setopt(c.FOLLOWLOCATION, 1)
        c.setopt(c.COOKIEFILE, '')
        c.setopt(c.TIMEOUT, 10)
        c.setopt(c.USERAGENT, '')
        c.setopt(pycurl.SSL_VERIFYPEER, 0)
        c.setopt(pycurl.SSL_VERIFYHOST, 0)
        c.perform()

        h.seek(0)

        location = ""
        location_arr = []
        final_url = ""

        h_str = h.getvalue().decode('utf-8')

        for l in h_str.splitlines():
            if "Location" in l:
                location = l.split(": ")[-1]
                location_arr.append(location)


        if len(location_arr) == 0:
            final_url = "http://" + s

        else:

            for i in range(0,len(location_arr)):
                if i == 0:
                    final_url += location_arr[i]
                else:
                    for j in range(0,len(location_arr[i])):
                        if j < len(location_arr[i-1]):
                            if location_arr[i][j] != location_arr[i-1][j]:
                                final_url += location_arr[i][j]
                        else:
                            final_url += location_arr[i][j]
        print("[CURL] HTTP redirected address -> " + final_url)
        print(final_url, file=curl_outs)
    except pycurl.error:
        #port 80 failed. Try port 443
        print("[CURL] Port 80 failed to connect. Trying port 443 ...")
        try:
            print("[CURL] Processing https://" + s)

            o = io.BytesIO()
            h = io.BytesIO()

            c = pycurl.Curl()
            host = "https://" + s
            c.setopt(c.URL, host)
            c.setopt(c.WRITEFUNCTION, o.write)
            c.setopt(c.HEADERFUNCTION, h.write)
            c.setopt(c.CONNECTTIMEOUT, 30)
            c.setopt(c.AUTOREFERER,1)
            c.setopt(c.FOLLOWLOCATION, 1)
            c.setopt(c.COOKIEFILE, '')
            c.setopt(c.TIMEOUT, 10)
            c.setopt(c.USERAGENT, '')
            c.setopt(pycurl.SSL_VERIFYPEER, 0)
            c.setopt(pycurl.SSL_VERIFYHOST, 0)
            c.perform()

            h.seek(0)

            location = ""
            location_arr = []
            final_url = ""

            h_str = h.getvalue().decode('utf-8')

            for l in h_str.splitlines():
                if "Location" in l:
                    location = l.split(": ")[-1]
                    location_arr.append(location)

            if len(location_arr) == 0:
                final_url = "https://" + s

            else:

                for i in range(0,len(location_arr)):
                    if i == 0:
                        final_url += location_arr[i]
                    else:
                        for j in range(0,len(location_arr[i])):
                            if j < len(location_arr[i-1]):
                                if location_arr[i][j] != location_arr[i-1][j]:
                                    final_url += location_arr[i][j]
                            else:
                                final_url += location_arr[i][j]

            print("[CURL] HTTPS redirected address -> " + final_url)
            print(final_url,file=curl_outs)
        except pycurl.error:
            print("[CURL] Port 443 failed to connect. Printing default https address -> https://" + s)
            print("https://" + s, file=curl_outs)

curl_outs.close()
ptr_outs.close()
