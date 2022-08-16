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
__version__ = "2.2.0"
__description__ = "Check IP or Domain reputation against 400+ open-source Blacklists."

# ---[ Initialize Colorama ]---
init(autoreset=True)

# ---[ Define program root directory ]---
prog_root = Path(__file__).resolve().parent


def argparser():
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
    required.add_argument("-q", help="query ip address or domain")
    optional.add_argument("--log", action="store_true", help="log results to file")
    optional.add_argument("--vt", action="store_true", help="check virustotal")

    group = optional.add_mutually_exclusive_group()
    group.add_argument("--fg", action="store_true", help="use freegeoip for geolocation")
    group.add_argument("--mx", nargs="+", metavar="FILE", help="geolocate multiple ip addresses or domains")

    parser._action_groups.append(optional)
    args = parser.parse_args()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    return args, parser


def multi_map_arg(arg):
    multi_map(input_file=arg)
    print(colored.stylize("\n--[ GeoIP Map File ]--", colored.attr("bold")))
    try:
        multi_map_file = Path("multi_map.html").resolve(strict=True)
    except FileNotFoundError:
        logger.info("[-] Geolocation map file was not created or does not exist.")
    else:
        logger.info(f"> Geolocation map file saved to: {multi_map_file}")
    sys.exit(1)


def vt_arg(arg, settings, workers):
    print(colored.stylize("\n--[ VirusTotal Detections ]--", colored.attr("bold")))

    with open(settings, encoding="utf-8") as api:
        vt_config = yaml.load(api)

    if not vt_config["VIRUS-TOTAL"]["api_key"]:
        logger.warning("Please add VirusTotal API key to the 'settings.yml' file, or add it below")
        user_vt_key = input("Enter key: ")
        vt_config["VIRUS-TOTAL"]["api_key"] = user_vt_key

        with open("settings.yml", "w", encoding="utf-8") as output:
            yaml.dump(vt_config, output)

    api_key = vt_config["VIRUS-TOTAL"]["api_key"]
    virustotal = VirusTotalChk(api_key)

    if DOMAIN.findall(arg):
        virustotal.vt_run("domains", arg)

    elif IP.findall(arg):
        virustotal.vt_run("ip_addresses", arg)

    elif URL.findall(arg):
        virustotal.vt_run("urls", arg)

    else:
        virustotal.vt_run("files", arg)
        print(colored.stylize("\n--[ Team Cymru Detection ]--", colored.attr("bold")))
        workers.tc_query(qry=arg)
        sys.exit("\n")


def domain_arg(workers, arg):
    print(colored.stylize("\n--[ Querying Domain Blacklists ]--", colored.attr("bold")))
    workers.spamhaus_dbl_worker()
    workers.blacklist_dbl_worker()

    print(colored.stylize(f"\n--[ WHOIS for {arg} ]--", colored.attr("bold")))
    workers.whois_query(arg)


def geomap_output():
    print(colored.stylize("--[ GeoIP Map File ]--", colored.attr("bold")))
    time_format = "%d %B %Y %H:%M:%S"
    try:
        ip_map_file = prog_root.joinpath("geomap/ip_map.html").resolve(strict=True)
    except FileNotFoundError:
        logger.warning("[-] Geolocation map file was not created/does not exist.\n")
    else:
        ip_map_timestamp = datetime.fromtimestamp(os.path.getctime(ip_map_file))
        logger.info(f"> Geolocation map file created: {ip_map_file} [{ip_map_timestamp.strftime(time_format)}]\n")


def main(settings):

    # Parse the arguments from the command line.
    args = argparser()[0]
    parser = argparser()[1]
    query = args.q

    # Initialize utilities
    workers = Workers(query)

    print(f"\n{Fore.GREEN}[+] Running checks...{Style.RESET_ALL}")

    if args.log:
        if not os.path.exists("logfile"):
            os.mkdir("logfile")
        dt_stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        handlers = logging.FileHandler(f"logfile/logfile_{dt_stamp}.txt", "w", "utf-8")
        handlers.setFormatter(logging.Formatter("[%(asctime)s %(levelname)s] %(message)s", datefmt="%m/%d/%Y %I:%M:%S"))
        logger.addHandler(handlers)

    if args.fg:
        map_free_geo(query)

    if args.mx:
        multi_map_arg(arg=args.mx[0])

    if args.vt:
        vt_arg(query, settings, workers)

    if DOMAIN.findall(query) and not EMAIL.findall(query):
        domain_arg(workers, query)

    elif IP.findall(query):
        workers.query_ip(query)

    elif NET.findall(query):
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
        logger.info(f"[-] {query} is not listed in any Blacklists\n")
    else:
        qry_format = Fore.YELLOW + query + Style.BRIGHT + Style.RESET_ALL

        dnsbl_matches_out = f"{Fore.WHITE}{Back.RED}{str(workers.dnsbl_matches)}{Style.BRIGHT}{Style.RESET_ALL}"
        bl_totals_out = f"{Fore.WHITE}{Back.RED}{str(bl_totals)}{Style.BRIGHT}{Style.RESET_ALL}"
        logger.info(f"> {qry_format} is listed in {dnsbl_matches_out} DNSBL lists and {bl_totals_out} Blacklists\n")

    # ---[ Geo Map output ]-------------------------------
    if args.fg or args.mx:
        geomap_output()


if __name__ == "__main__":

    BANNER = r"""
   ________              __      ____
  / ____/ /_  ___  _____/ /__   / __ \___  ____
 / /   / __ \/ _ \/ ___/ //_/  / /_/ / _ \/ __ \
/ /___/ / / /  __/ /__/ ,<    / _, _/  __/ /_/ /
\____/_/ /_/\___/\___/_/|_|  /_/ |_|\___/ .___/
                                       /_/
"""

    print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}")
    print("Check IP and Domain Reputation")

    # ---[ Python v3.7+ check ]---
    if sys.version_info[0] == 3 and sys.version_info[1] <= 8:
        print("\n[x] Please use python version 3.8 or higher.\n")

    # ---[ Configuration Parser ]---
    yaml = YAML()
    settings = prog_root.joinpath("settings.yml")

    # Create settings.yml file if it does not exist.
    # fmt: off
    TEXT = """# Add API Key after 'api_key:'
# Example: api_key: 23efd1000l3eh444f34l0000kfe56kec0

VIRUS-TOTAL:
    api_key: """
    # fmt: on

    if not settings.exists():
        print(f"\n{Fore.YELLOW}[-]{Fore.RESET} The 'settings.yml' file is missing.")
        with open(settings, "w", encoding="utf-8") as fileobj:
            fileobj.writelines(TEXT)
        print(f"{Fore.GREEN}[+]{Fore.RESET} Created 'settings.yml' file.\n")

    main(settings)
