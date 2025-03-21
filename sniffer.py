import socket
import  subprocess
import requests
import geoip2.database
from os import system, getlogin
from colorama import Fore as fg


# Tool global variables:
username = getlogin()

# GeoIP Databases:
asn_db = 'geoip_db/GeoLite2-ASN.mmdb'
country_db = 'geoip_db/GeoLite2-Country.mmdb'
city_db = 'geoip_db/GeoLite2-City.mmdb'


def TOOL_BANNER():
    return f"""{fg.RED}
                    ┏┓┏┓┏┳┓┳┓┏┓┏┓┳┳┏┓      ┳┏┓  ┏┓┳┓┳┏┓┏┓┏┓┳┓
                    ┣┫┗┓ ┃ ┣┫┣┫┣ ┃┃┗┓  ━━  ┃┃┃  ┗┓┃┃┃┣ ┣ ┣ ┣┫
                    ┛┗┗┛ ┻ ┛┗┛┗┗┛┗┛┗┛      ┻┣┛  ┗┛┛┗┻┻ ┻ ┗┛┛┗
              {fg.WHITE}Developed by {fg.GREEN}Astraeus {fg.WHITE}- type [{fg.GREEN}help{fg.WHITE}] to show help menu"""


def HELP_BANNER():
    return f"""{fg.WHITE}
    IP Sniffer for use in Online Chats, such as OmeTV and Omegle.
    Over time there will be updates to expand its capacity.

    Commands:
    {fg.GREEN}[exit{fg.WHITE}] - to exit the tool
    {fg.GREEN}[clear{fg.WHITE}] - to clear the tool screen
    {fg.GREEN}[start{fg.WHITE}] - to start capturing IPs
    """


# Search the IP in the database to locate it.
def ip_lookup(ip):
    read_asn = geoip2.database.Reader(asn_db)
    read_country = geoip2.database.Reader(country_db)
    read_city = geoip2.database.Reader(city_db)

    try:
        infos_asn = read_asn.asn(ip)
        infos_country = read_country.country(ip)
        infos_city = read_city.city(ip)
        print(f"""
        {fg.GREEN}IP: {fg.WHITE}{ip}
        {fg.GREEN}Cidade: {fg.WHITE}{infos_city.city.name}
        {fg.GREEN}Estado: {fg.WHITE}{infos_city.subdivisions.most_specific.name}
        {fg.GREEN}País: {fg.WHITE}{infos_country.country.name}
        {fg.GREEN}Organização: {fg.WHITE}{infos_asn.autonomous_system_organization}
        {fg.GREEN}Latitude: {fg.WHITE}{infos_city.location.latitude}
        {fg.GREEN}Longitude: {fg.WHITE}{infos_city.location.longitude}
        """)

    except geoip2.errors.AddressNotFoundError:
        print(f"{fg.RED} - IP {fg.WHITE}{ip} {fg.RED}Unable to locate!")

    read_asn.close()
    read_country.close()
    read_city.close()


# Use Wireshark's TShark to search for packets.
def sniffing():
    try:
        tshark_path = r"C:\System\Hacking\Wireshark\tshark.exe -i 5"
        process = subprocess.Popen(tshark_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        my_ip = socket.gethostbyname(socket.gethostname())
        ip_list = []

        for line in iter(process.stdout.readline, b""):
            columns = str(line).split(" ")

            if "SKYPE" in columns or "UDP" in columns:
                if "->" in columns:
                    ip = columns[columns.index("->") - 1]

                elif "\\xe2\\x86\\x92" in columns:
                    ip = columns[columns.index("\\xe2\\x86\\x92") - 1]
                    
                else:
                    continue

                if ip not in ip_list:
                    ip_list.append(ip)
                    ip_lookup(ip)

    except Exception as error:
        print(error)



class Main:
    def __init__(self):
        system('cls & title Astraeus - IP Sniffer')
        print(TOOL_BANNER())
        self.input_cmd()

    def input_cmd(self):
        while True:
            print()
            print(f" {fg.RED}┌─({fg.GREEN}{username}{fg.RED})~[]")
            cmd = input(f" {fg.RED}└───:: {fg.WHITE}").strip().lower()
            print()

            if cmd == 'exit':
                print(F"{fg.RED}Exiting...")
                exit()
            
            elif cmd == 'clear':
                Main()

            elif cmd == 'help':
                print(HELP_BANNER())

            elif cmd == 'start':
                sniffing()

            else:
                print(f"{fg.RED}Please enter a valid command.")


if __name__ == '__main__':
    try:
        Main()
    except KeyboardInterrupt:
        print(f"{fg.RED}Exiting...")

