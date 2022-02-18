import gzip
import json
import os
import shutil
import time
from pathlib import Path

import dns.resolver
import geoip2.database
import requests
from folium import Map, Marker, Popup

from core.utils import DOMAIN, Helpers, logger

helpers = Helpers()

# Working program directories
prog_root = Path(os.path.dirname(os.path.dirname(__file__)))
geomap_root = prog_root / "geomap"

# Create the geomap directory
if not os.path.exists(geomap_root):
    os.mkdir(geomap_root)

# Working files
gl_zipped = geomap_root / "GeoLite2-City.mmdb.gz"
gl_file = geomap_root / "GeoLite2-City.mmdb"
ip_map_file = os.path.join(geomap_root, "ip_map.html")


def geo_query_map(qry):
    # Check if Geolite file exists
    geolite_check()

    # Used to resolve domains to ip address
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "8.8.4.4"]
    if DOMAIN.findall(qry):
        try:
            response = resolver.query(qry, "A")
            qry = response.rrset[-1]
            map_maxmind(str(qry))
        except dns.resolver.NoAnswer as err:
            logger.error(f"[error] {err}")
    else:
        map_maxmind(qry)


# ---[ GeoLite File Check/Download ]---
def geolite_check():
    if os.path.exists(gl_zipped):
        print(f"{gl_zipped} exists, unzipping...")
        with gzip.open(gl_zipped, "rb") as f_in:
            with open(gl_file, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(gl_zipped)

    if not os.path.exists(gl_file):
        GEO_URL = "https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz"
        print("-" * 80)
        logger.warning(f"[-] {gl_file} does not exist.")
        geoip_download = input("\n[+] Would you like to download the GeoLite2-City file (yes/no)? ")
        if geoip_download.lower() == "yes":
            os.chdir(geomap_root)
            helpers.download_file(GEO_URL)
            with gzip.open(gl_zipped, "rb") as f_in, open(gl_file, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(gl_zipped)


# ---[ Geolocate and Map IP Address ]---
# Ref: https://github.com/maxmind/GeoIP2-python
def map_maxmind(qry):
    try:
        geo_reader = geoip2.database.Reader(gl_file)
        ip_map = Map([40, -5], tiles="OpenStreetMap", zoom_start=3)
        response = geo_reader.city(qry)
        if response.location:
            lat = response.location.latitude
            lon = response.location.longitude
            popup = Popup(qry)

            Marker([lat, lon], popup=popup).add_to(ip_map)
            ip_map.save(ip_map_file)
    except geoip2.errors.AddressNotFoundError:
        logger.warning(f"[-] Address {qry} is not in the geoip database.")
    except FileNotFoundError:
        logger.info("\n[*] Please download the GeoLite2-City database file: ")
        print("    --> https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz")
        time.sleep(2)


def map_free_geo(qry):
    ip_map = Map([40, -5], tiles="OpenStreetMap", zoom_start=3)
    freegeoip = f"https://freegeoip.live/json/{qry}"
    try:
        req = requests.get(freegeoip)
        req.raise_for_status()
    except ConnectionError as err:
        logger.warning(f"[error] {err}\n")
    else:
        if req.status_code == 200:
            data = json.loads(req.content.decode("utf-8"))
            lat = data["latitude"]
            lon = data["longitude"]
            Marker([lat, lon], popup=qry).add_to(ip_map)
            ip_map.save(ip_map_file)


def multi_map(input_file):
    os.chdir(geomap_root)

    # Check if Geolite file exists
    geolite_check()

    file_path = os.path.abspath(os.pardir)
    input_file = f"{file_path}/{input_file}"
    with open(input_file, encoding="utf-8") as file_obj:
        line = [line.strip() for line in file_obj.readlines()]
        ip_map = Map([40, -5], tiles="OpenStreetMap", zoom_start=3)
        try:
            geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
            for address in line:
                response = geo_reader.city(address)
                if response.location:
                    logger.success(f"[+] Mapping {address}")
                    lat = response.location.latitude
                    lon = response.location.longitude
                    Marker([lat, lon], popup=address).add_to(ip_map)
                    ip_map.save("multi_map.html")
        except ValueError as err:
            print(f"[error] {err}")
        except geoip2.errors.AddressNotFoundError:
            logger.warning("[-] Address is not in the geoip database.")
        except FileNotFoundError:
            geolite_check()
