import json
import os
from ipaddress import IPv4Address
from pathlib import Path

import colored
import dns.resolver
import requests
from folium import Map, Marker

from core.utils import DOMAIN, IP, Helpers, Workers, logger

helpers = Helpers()

# Working program directories
prog_root = Path(os.path.dirname(os.path.dirname(__file__)))
geomap_root = prog_root / "geomap"

# Create the geomap directory
if not os.path.exists(geomap_root):
    os.mkdir(geomap_root)

# Working files
ip_map_file = os.path.join(geomap_root, "ip_map.html")
multi_map_file = os.path.join(geomap_root, "multi_map.html")


def geo_resolver(qry, whois=None):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    try:
        dns_resp = list(resolver.query(qry, "A"))[-1]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    else:
        if whois:
            workers = Workers(qry)
            return workers.get_dns_info(dns_resp, qry)
        return dns_resp


def map_free_geo(qry):
    if DOMAIN.findall(qry):
        qry = geo_resolver(qry)

    if qry is not None:
        freegeoip = f"https://freegeoip.live/json/{qry}"
        try:
            req = requests.get(freegeoip)
            req.raise_for_status()
        except ConnectionError as err:
            logger.warning(f"[error] {err}\n")
        else:
            if req.status_code == 200:
                map_maker(req, qry)


def map_maker(req, qry):
    data = json.loads(req.content.decode("utf-8"))
    lat = data["latitude"]
    lon = data["longitude"]
    mapobj = Map(location=[lat, lon], zoom_start=3)
    Marker(location=[lat, lon], popup=qry).add_to(mapobj)
    mapobj.save(ip_map_file)


def multi_map(input_file):
    os.chdir(geomap_root)
    file_path = os.path.abspath(os.pardir)
    input_file = f"{file_path}/{input_file}"
    mapobj = Map(location=[40, -5], zoom_start=3)

    with open(input_file, encoding="utf-8") as file_obj:
        line = [line.strip() for line in file_obj.readlines()]
        for address in line:
            workers = Workers(address)
            if DOMAIN.findall(address):
                print(colored.stylize("\n--[ Querying Domain Blacklists ]--", colored.attr("bold")))
                workers.spamhaus_dbl_worker()
                workers.blacklist_dbl_worker()
                if workers.whois_query(address):
                    print(workers.whois_query(address))

                qry = geo_resolver(address)
                if qry is not None:
                    logger.success(f"[+] Mapping {address} -> {qry}")
                    try:
                        freegeoip = f"https://freegeoip.live/json/{qry}"
                        req = requests.get(freegeoip)
                        req.raise_for_status()
                    except ConnectionError as err:
                        logger.warning(f"[error] {err}\n")
                    else:
                        data = json.loads(req.content.decode("utf-8"))
                        lat = data["latitude"]
                        lon = data["longitude"]
                        html = f"""{address}<br>
                        {qry}"""
                        Marker(location=[lat, lon], popup=html).add_to(mapobj)
                        mapobj.save(multi_map_file)

            if IP.findall(address) and IPv4Address(address):
                workers.query_ip(address)
                if address is not None:
                    logger.success(f"[+] Mapping {address}")
                    try:
                        freegeoip = f"https://freegeoip.live/json/{address}"
                        req = requests.get(freegeoip)
                        req.raise_for_status()
                    except ConnectionError as err:
                        logger.warning(f"[error] {err}\n")
                    else:
                        data = json.loads(req.content.decode("utf-8"))
                        lat = data["latitude"]
                        lon = data["longitude"]
                        Marker(location=[lat, lon], popup=address).add_to(mapobj)
                        mapobj.save(multi_map_file)
