import sys
import time
import json
import subprocess
import maxminddb



def ipv4_addresses(dic,line):
    ipv4addresses = set()
    for dnsresolver in public_dns_resolvers:
        try:
            ip4result = subprocess.check_output(["nslookup","-type=A",line,dnsresolver], timeout=4, stderr=subprocess.STDOUT).decode("utf-8")
            chunks = ip4result.split("\n")
            for i in range(len(chunks)):
                chunk = chunks[i]
                if len(chunk) > 5 and chunk[:5] == "Name:":
                    ipv4addresses.add(chunks[i+1][9:])
        except subprocess.TimeoutExpired:
            print("Failed to lookup IPv4 address of " + line + " with DNS resolver " + dnsresolver)
        except:
            print("Failed to lookup IPv4 address of " + line + " with DNS resolver " + dnsresolver + " not because of timeout")
    dic[line]["ipv4_addresses"] = list(ipv4addresses)


def ipv6_addresses(dic,line):
    ipv6addresses = set()
    for dnsresolver in public_dns_resolvers:
        try:
            ip6result = subprocess.check_output(["nslookup","-type=AAAA",line,dnsresolver], timeout=4, stderr=subprocess.STDOUT).decode("utf-8")
            chunks = ip6result.split("\n")
            for i in range(len(chunks)):
                chunk = chunks[i]
                if len(chunk) > 5 and chunk[:5] == "Name:":
                    ipv6addresses.add(chunks[i+1][9:])
        except subprocess.TimeoutExpired:
            print("Failed to lookup IPv6 address of " + line + " with DNS resolver " + dnsresolver)
        except:
            print("Failed to lookup IPv6 address of " + line + " with DNS resolver " + dnsresolver + " not because of timeout")
    dic[line]["ipv6_addresses"] = list(ipv6addresses)


def http_server(dic,line):
    link = "http://" + line
    try:
        response = subprocess.check_output(["curl","-I",link], timeout=4, stderr=subprocess.STDOUT).decode("utf-8")
        chunks = response.split("\r\n")
        inchunkserver = False
        for chunk in chunks:
            if len(chunk) > 8 and (chunk[:8] == "server: " or chunk[:8] == "Server: "):
                dic[line]["http_server"] = chunk[8:]
                inchunkserver = True
        if not inchunkserver:
            dic[line]["http_server"] = None

    except subprocess.TimeoutExpired:
        print("Failed to lookup server header of " + link + " with curl because of timeout")
        dic[line]["http_server"]=None



def insecure_http(dic,line):
    link = "http://" + line
    try:
        response = subprocess.check_output(["curl","-I",link], timeout=4, stderr=subprocess.STDOUT).decode("utf-8")
        dic[line]["insecure_http"] = True
    except subprocess.TimeoutExpired:
        print("Failed to lookup server header of " + link + " with curl because of timeout")
        dic[line]["insecure_http"]=False

    except:
        print(line + " failed insecure_http not because of timeout")
        dic[line]["insecure_http"] = False



def redirect_to_https(dic,line):
    def do(orig,line,ctr):
        if ctr == 10:
            dic[orig]["redirect_to_https"] = False
            return
        try:
            response = subprocess.check_output(["curl","-I",line], timeout=4, stderr=subprocess.STDOUT).decode("utf-8")
            chunks = response.split("\r\n")
            start = chunks[0].split("HTTP")[1]
            if len(start) > 7 and start[:7] == "/1.1 30":
                for chunk in chunks:
                    if len(chunk) > 10 and (chunk[:10] == "Location: "):
                        if chunk[10:16] == "https:":
                            dic[orig]["redirect_to_https"] = True
                            return
                        else:
                            do(orig,chunk[10:],ctr+ 1)
                            return
            dic[orig]["redirect_to_https"] = False
            return
        except subprocess.TimeoutExpired:
            print(orig + " failed redirect_to_https bc of timeout")
            dic[orig]["redirect_to_https"]=False
            return
        except:
            print(orig + " failed redirect_to_https not because of timeout")
            dic[orig]["redirect_to_https"] = False
            return

    if dic[line]["insecure_http"] == False:
        dic[line]["redirect_to_https"] = False
        return

    do(line,"http://" + line,0)


def rtt_range(dic,line):
    ipv4_addresses = dic[line]["ipv4_addresses"]
    ports = ["80","443","22"]
    rtt_min = None
    rtt_max = None
    for ipv4 in ipv4_addresses:
        for port in ports:
            try:
                response = subprocess.check_output(("sh -c \"time echo -e '\\x1dclose\\x0d' | telnet " + ipv4 + " "  + port + "\""), shell=True, timeout=4, stderr=subprocess.STDOUT).decode("utf-8")
                chunks = response.split("\n")
                time = float(chunks[7][8:-1]) * 1000
                if rtt_min is None or time < rtt_min: rtt_min = time
                if rtt_max is None or time > rtt_max: rtt_max = time
                break

            except subprocess.TimeoutExpired:
                print(ipv4 + " of " + line + " failed rtt_range because of timeout")

            except:
                print(ipv4 + " of " + " failed rtt_range not because of timeout")

    if rtt_min is None and rtt_max is None:
        dic[line]["rtt_range"] = None
    else:
        dic[line]["rtt_range"] = (rtt_min,rtt_max)






def geo_locations(dic,line):
    ipv4_addresses = dic[line]["ipv4_addresses"]
    locations = set()
    with maxminddb.open_database("GeoLite2-City.mmdb") as reader:
        for ipv4 in ipv4_addresses:
            locdic = reader.get(ipv4)
            if 'city' not in locdic:
                continue
            city = locdic["city"]["names"]["en"]
            province = locdic["subdivisions"][0]["names"]["en"]
            country = locdic["country"]["names"]["en"]
            locations.add((city,province,country))
    dic[line]["geo_locations"] = list(locations)





public_dns_resolvers = ["208.67.222.222","1.1.1.1","8.8.8.8","8.26.56.26","9.9.9.9","64.6.65.6","91.239.100.100","185.228.168.168","77.88.8.7","156.154.70.1","198.101.242.72","176.103.130.130"]
inputtxtname = sys.argv[1]
outputfilename = sys.argv[2]
inpath = './' + inputtxtname
output = './'+ outputfilename
dic = {}
with open(inpath,"r") as file:
    while True:
        line = file.readline().strip()
        if not line: break
        dic[line] = {"scan_time":time.time()}

        ipv4_addresses(dic,line)

        # ipv6_addresses(dic,line)

        # http_server(dic,line)

        # insecure_http(dic,line)

        # redirect_to_https(dic,line)

        rtt_range(dic,line)

        # geo_locations(dic,line)





with open(output, "w") as file:
    json.dump(dic,file,sort_keys=True,indent=4)
