import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import colored
from colorama import Back, Fore, Style, init
from ruamel.yaml import YAML

from core.geomap import map_free_geo, multi_map
from core.utils import DOMAIN, EMAIL, IP, NET, URL, Workers, logger
from core.vt_check import VirusTotalChk

__author__ = "DFIRSec (@pulsecode)"
__version__ = "2.0"
__description__ = "Check IP or Domain reputation against 400+ open-source Blacklists."

# ---[ Python v3 check ]---
if sys.version_info[0] == 3 and sys.version_info[1] <= 5:
    print("\n[x] Please use python version 3.6 or higher.\n")
    sys.exit()

# ---[ Initialize Colorama ]---
init(autoreset=True)

# ---[ Define program root directory ]---
prog_root = Path(__file__).resolve().parent

# ---[ Configuration Parser ]---
yaml = YAML()
settings = prog_root.joinpath("settings.yml")
with open(settings, encoding="utf-8") as api:
    config = yaml.load(api)


def main():
    banner = r"""
   ________              __      ____
  / ____/ /_  ___  _____/ /__   / __ \___  ____
 / /   / __ \/ _ \/ ___/ //_/  / /_/ / _ \/ __ \
/ /___/ / / /  __/ /__/ ,<    / _, _/  __/ /_/ /
\____/_/ /_/\___/\___/_/|_|  /_/ |_|\___/ .___/
                                       /_/
"""

    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    print("Check IP and Domain Reputation")

    parser = argparse.ArgumentParser(
        description="Check IP or Domain Reputation",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
    Options
    --------------------
    freegeoip [freegeoip.live]  - free/opensource geolocation service
    virustotal [virustotal.com] - online multi-antivirus scan engine

    * NOTE:
    Use of the VirusTotal option requires an API key.
    The service is "free" to use, however you must register
    for an account to receive an API key.""",
    )

    optional = parser._action_groups.pop()
    required = parser.add_argument_group("required arguments")
    required.add_argument("query", help="query ip address or domain")
    optional.add_argument("--log", action="store_true", help="log results to file")
    optional.add_argument("--vt", action="store_true", help="check virustotal")

    group = optional.add_mutually_exclusive_group()
    group.add_argument("--fg", action="store_true", help="use freegeoip for geolocation")
    group.add_argument("--mx", nargs="+", metavar="FILE", help="geolocate multiple ip addresses or domains")

    parser._action_groups.append(optional)
    args = parser.parse_args()
    qry = args.query

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    # Initialize utilities
    workers = Workers(qry)

    print(f"\n{Fore.GREEN}[+] Running checks...{Style.RESET_ALL}")

    if args.log:
        if not os.path.exists("logfile"):
            os.mkdir("logfile")
        dt_stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        handlers = logging.FileHandler(f"logfile/logfile_{dt_stamp}.txt", "w", "utf-8")
        handlers.setFormatter(logging.Formatter("[%(asctime)s %(levelname)s] %(message)s", datefmt="%m/%d/%Y %I:%M:%S"))
        logger.addHandler(handlers)

    if args.fg:
        map_free_geo(qry)

    if args.mx:
        print(colored.stylize("\n--[ Processing Geolocation Map ]--", colored.attr("bold")))
        multi_map(input_file=args.mx[0])
        print(colored.stylize("\n--[ GeoIP Map File ]--", colored.attr("bold")))
        try:
            multi_map_file = Path("multi_map.html").resolve(strict=True)
        except FileNotFoundError:
            logger.info("[-] Geolocation map file was not created or does not exist.")
        else:
            logger.info(f"> Geolocation map file saved to: {multi_map_file}")
        sys.exit(1)

    if args.vt:
        print(colored.stylize("\n--[ VirusTotal Detections ]--", colored.attr("bold")))
        if not config["VIRUS-TOTAL"]["api_key"]:
            logger.warning("Please add VirusTotal API key to the 'settings.yml' file, or add it below")
            user_vt_key = input("Enter key: ")
            config["VIRUS-TOTAL"]["api_key"] = user_vt_key

            with open("settings.yml", "w", encoding="utf-8") as output:
                yaml.dump(config, output)

        api_key = config["VIRUS-TOTAL"]["api_key"]
        virustotal = VirusTotalChk(api_key)
        if DOMAIN.findall(qry):
            virustotal.vt_run("domains", qry)
        elif IP.findall(qry):
            virustotal.vt_run("ip_addresses", qry)
        elif URL.findall(qry):
            virustotal.vt_run("urls", qry)
        else:
            virustotal.vt_run("files", qry)
            print(colored.stylize("\n--[ Team Cymru Detection ]--", colored.attr("bold")))
            workers.tc_query(qry=qry)
            sys.exit("\n")

    if DOMAIN.findall(qry) and not EMAIL.findall(qry):
        print(colored.stylize("\n--[ Querying Domain Blacklists ]--", colored.attr("bold")))
        workers.spamhaus_dbl_worker()
        workers.blacklist_dbl_worker()
        print(colored.stylize(f"\n--[ WHOIS for {qry} ]--", colored.attr("bold")))
        workers.whois_query(qry)

    elif IP.findall(qry):
        # Check if cloudflare ip
        print(colored.stylize("\n--[ Using Cloudflare? ]--", colored.attr("bold")))
        if workers.cflare_results(qry):
            logger.info("Cloudflare IP: Yes")
        else:
            logger.info("Cloudflare IP: No")

        print(colored.stylize("\n--[ Querying DNSBL Lists ]--", colored.attr("bold")))
        workers.dnsbl_mapper()
        workers.spamhaus_ipbl_worker()
        print(colored.stylize("\n--[ Querying IP Blacklists ]--", colored.attr("bold")))
        workers.blacklist_ipbl_worker()

    elif NET.findall(qry):
        print(colored.stylize("\n--[ Querying NetBlock Blacklists ]--", colored.attr("bold")))
        workers.blacklist_netblock_worker()

    else:
        print(f"{Fore.YELLOW}[!] Please enter a valid query -- Domain or IP address{Style.RESET_ALL}")
        print("=" * 60, "\n")
        parser.print_help()
        parser.exit()

    # ---[ Results output ]-------------------------------
    print(colored.stylize("\n--[ Results ]--", colored.attr("bold")))
    totals = workers.dnsbl_matches + workers.bl_matches
    bl_totals = workers.bl_matches
    if totals == 0:
        logger.info(f"[-] {qry} is not listed in any Blacklists\n")
    else:
        qry_format = Fore.YELLOW + qry + Style.BRIGHT + Style.RESET_ALL

        dnsbl_matches_out = f"{Fore.WHITE}{Back.RED}{str(workers.dnsbl_matches)}{Style.BRIGHT}{Style.RESET_ALL}"
        bl_totals_out = f"{Fore.WHITE}{Back.RED}{str(bl_totals)}{Style.BRIGHT}{Style.RESET_ALL}"
        logger.info(f"> {qry_format} is listed in {dnsbl_matches_out} DNSBL lists and {bl_totals_out} Blacklists\n")

    # ---[ Geo Map output ]-------------------------------
    if args.fg or args.mx:
        print(colored.stylize("--[ GeoIP Map File ]--", colored.attr("bold")))
        time_format = "%d %B %Y %H:%M:%S"
        try:
            ip_map_file = prog_root.joinpath("geomap/ip_map.html").resolve(strict=True)
        except FileNotFoundError:
            logger.warning("[-] Geolocation map file was not created/does not exist.\n")
        else:
            ip_map_timestamp = datetime.fromtimestamp(os.path.getctime(ip_map_file))
            logger.info(f"> Geolocation map file created: {ip_map_file} [{ip_map_timestamp.strftime(time_format)}]\n")


if __name__ == "__main__":
    main()
