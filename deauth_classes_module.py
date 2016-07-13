class WirelessLocalAreaNetwork(object):
    def __init__(self, network_id, bssid, eligible_hosts):
        self.network_id = network_id
        self.bssid = bssid
        self.eligible_hosts = eligible_hosts

    def display_eligible_hosts(self):
        print('ID'+'\t'+'MAC'+'\t\t\t'+'IPv4'+'\t\t\t'+'HOST')
        for i in range(0, len(self.eligible_hosts)):
            print(str(i) + '\t' + self.eligible_hosts[i].mac_address + '\t' + self.eligible_hosts[i].ip_address + '\t\t' + self.eligible_hosts[i].host_name)

class EligibleHost(object):
    def __init__(self, host_name, ip_address, mac_address):
        self.host_name = host_name
        self.ip_address = ip_address
        self.mac_address = mac_address
