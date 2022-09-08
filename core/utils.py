import asyncio
import contextlib
import logging
import pathlib
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import responses
from ipaddress import AddressValueError, IPv4Address, IPv4Network, ip_address

import asyncwhois
import colored
import coloredlogs
import dns.resolver
import requests
import verboselogs
from tqdm import tqdm

from core.feeds import CFLARE_IPS, DNSBL_LISTS, DOM_LISTS, IP_BLOCKS, IP_LISTS, SPAMHAUS_DOM, SPAMHAUS_IP

logger = verboselogs.VerboseLogger(__name__)
logger.setLevel(logging.INFO)
coloredlogs.install(
    level=None,
    logger=logger,
    fmt="%(message)s",
    level_styles={
        "notice": {"color": "black", "bright": True},
        "warning": {"color": "yellow"},
        "success": {"color": "green", "bold": True},
        "error": {"color": "red"},
    },
)


class Helpers:
    # ---[ Regex Parser ]---
    @staticmethod
    def regex(_type):
        # ref: http://data.iana.org/TLD/tlds-alpha-by-domain.txt
        dir_path = pathlib.Path(__file__).parent
        with open(dir_path / "tlds.txt", encoding="utf-8") as file_obj:
            tlds = file_obj.read()
        pattern = dict(
            ip_addr=r"(^(\d{1,3}\.){0,3}\d{1,3}$)",
            ip_net=r"(^(\d{1,3}\.){0,3}\d{1,3}/\d{1,2}$)",
            domain=rf"([A-Za-z0-9]+(?:[\-|\.][A-Za-z0-9]+)*(?:\[\.\]|\.)(?:{tlds}))",
            email=r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,5}$)",
            url=r"(http[s]?:\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)",
        )
        try:
            pattern = re.compile(pattern[_type])
        except re.error:
            print("[!] Invalid input specified.")
            sys.exit(0)
        return pattern

    # ---[ Common User-Agents ]---
    @staticmethod
    def headers():
        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 "
            "Safari/537.36 Edge/12.246",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 "
            "Safari/537.36",
            "Mozilla/5.0 (X11; Linux i686; rv:30.0) Gecko/20100101 Firefox/42.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/40.0.2214.38 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
        ]
        return {"user-agent": random.choice(ua_list)}

    # ---[ File Downloader NO LONGER USED ]---
    @staticmethod
    def download_file(url):
        local_file = url.split("/")[-1]
        try:
            resp = requests.get(url, local_file, stream=True)
            size = int(resp.headers["content-length"])
            pbar = tqdm(
                iterable=resp.iter_content(chunk_size=1024), total=size, unit="B", unit_scale=True, unit_divisor=1024
            )
            if resp.status_code == 403:
                logger.info(responses[403])
                sys.exit()
            elif resp.status_code == 200:
                with open(local_file, "wb") as file_obj:
                    for data in pbar:
                        file_obj.write(data)
                        pbar.update(len(data))
            else:
                logger.info((resp.status_code, responses[resp.status_code]))
                sys.exit()
        except requests.exceptions.Timeout:
            logger.notice(f"[timeout] {url}")
        except requests.exceptions.HTTPError as err:
            logger.error(f"[error] {err}")
        except requests.exceptions.ConnectionError as err:
            logger.error(f"[error] {err}")
        except requests.exceptions.RequestException as err:
            logger.critical(f"[critical] {err}")


# ---[ Helper objects ]---
helpers = Helpers()
IP = helpers.regex(_type="ip_addr")
NET = helpers.regex(_type="ip_net")
DOMAIN = helpers.regex(_type="domain")
URL = helpers.regex(_type="url")
EMAIL = helpers.regex(_type="email")


class Workers:
    def __init__(self, qry):
        self.query = qry
        self.dnsbl_matches = 0
        self.bl_matches = 0

    # ---[ Query DNSBL Lists ]---
    def dnsbl_query(self, blacklist):
        host = "".join(self.query)

        # Return Codes
        codes = [
            "127.0.0.2",
            "127.0.0.3",
            "127.0.0.4",
            "127.0.0.5",
            "127.0.0.6",
            "127.0.0.7",
            "127.0.0.9",
            "127.0.1.4",
            "127.0.1.5",
            "127.0.1.6",
            "127.0.0.10",
            "127.0.0.11",
            "127.0.0.39",
            "127.0.1.103",
            "127.0.1.104",
            "127.0.1.105",
            "127.0.1.106",
        ]

        with contextlib.suppress(
            dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer
        ):
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            resolver = dns.resolver.Resolver()
            qry = ""
            if helpers.regex(_type="ip_addr").findall(self.query):
                try:
                    qry = ip_address(host).reverse_pointer.strip(".in-addr.arpa") + "." + blacklist
                except ValueError:
                    sys.exit(f"{host} is not a valid IP address")
            elif helpers.regex(_type="domain").findall(self.query):
                qry = ".".join(host.split(".")) + "." + blacklist
            answer = resolver.query(qry, "A")
            if any(str(answer[0]) in s for s in codes):
                logger.info(f"\u2716  {self.query} --> {blacklist}")
                self.dnsbl_matches += 1

    def dnsbl_mapper(self):
        with ThreadPoolExecutor(max_workers=50) as executor:
            dnsbl_map = {executor.submit(self.dnsbl_query, url): url for url in DNSBL_LISTS}
            for future in as_completed(dnsbl_map):
                future.result()

    def spamhaus_ipbl_worker(self):
        self.dnsbl_query(SPAMHAUS_IP)

    def spamhaus_dbl_worker(self):
        self.dnsbl_query(SPAMHAUS_DOM)

    def bl_mapper(self, query_type, list_type, list_name):
        """Query Blacklists."""
        with ThreadPoolExecutor(max_workers=50) as executor:
            mapper = {executor.submit(query_type, url): url for url in list_type}
            for future in as_completed(mapper):
                future.result()
            if self.bl_matches == 0:
                logger.info(f"[-] {self.query} is not listed in active {list_name}")

    def blacklist_worker(self, blacklist):
        try:
            req = requests.get(blacklist, headers=helpers.headers(), timeout=3)
            req.encoding = "utf-8"
            if match := re.findall(self.query, req.text):
                logger.warning(f"\u2716  {self.query} --> {blacklist}")
                self.bl_matches += 1
        except AddressValueError as err:
            logger.error(f"[-] {err}")
        except requests.exceptions.Timeout:
            logger.notice(f"[-] {blacklist}")
        except requests.exceptions.HTTPError as err:
            logger.error(f"[-] {err}")
        except requests.exceptions.ConnectionError:
            logger.error(f"[-] Problem connecting to {blacklist}")
        except requests.exceptions.RequestException as err:
            logger.critical(f"[critical] {err}")

    def blacklist_query(self, blacklist):
        self.blacklist_worker(blacklist)

    def blacklist_dbl_worker(self):
        self.bl_mapper(query_type=self.blacklist_query, list_type=DOM_LISTS, list_name="Domain Blacklists")

    def blacklist_ipbl_worker(self):
        self.bl_mapper(query_type=self.blacklist_query, list_type=IP_LISTS, list_name="IP Blacklists")

    def blacklist_ipblock_query(self, blacklist):
        self.blacklist_worker(blacklist)

    def blacklist_netblock_worker(self):
        self.bl_mapper(query_type=self.blacklist_ipblock_query, list_type=IP_BLOCKS, list_name="NetBlock Blacklists")

    def whois_query(self, qry):
        try:
            dns_resp = list(dns.resolver.resolve(qry, "A"))
        except dns.resolver.NXDOMAIN:
            logger.error(f"[-] Domain '{qry}' does not appear to be a registered domain\n")
            time.sleep(1)  # prevents [WinError 10054]
        except dns.resolver.NoAnswer:
            logger.error(f"[-] No answer for domain {qry}\n")
        except dns.resolver.Timeout:
            logger.error(f"[-] Timeout for resolving domain {qry}\n")
        else:
            self.get_dns_info(dns_resp, qry)

    def get_dns_info(self, dns_resp, qry):
        print(f"IP Address: {dns_resp[0]}")

        # Check if cloudflare ip
        if self.cflare_results(dns_resp[0]):
            logger.info("Cloudflare IP: Yes")
        else:
            logger.info("Cloudflare IP: No")

        loop = asyncio.get_event_loop()
        who = loop.run_until_complete(asyncwhois.aio_whois_domain(qry))
        print("Registered to:", who.parser_output["registrant_organization"])
        print("Registrar:", who.parser_output["registrar"])
        print("Organization:", who.parser_output["registrant_organization"])
        print("Updated:", who.parser_output["updated"])
        print("Created:", who.parser_output["created"])
        print("Expires:", who.parser_output["expires"])
        print("Email Address:", who.parser_output["registrant_email"])

    # ----[ CLOUDFLARE CHECK SECTION ]---
    @staticmethod
    def chk_cflare_list(qry):
        for net in CFLARE_IPS:
            if IPv4Address(qry) in IPv4Network(net):
                yield True

    def cflare_results(self, qry):
        for ip_address in self.chk_cflare_list(qry):
            return ip_address

    @staticmethod
    def tc_query(qry):
        cymru = f"{qry}.malware.hash.cymru.com"
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            answer = resolver.resolve(cymru, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
            pass
        else:
            if answer:
                logger.error("\u2718 malware.hash.cymru.com: MALICIOUS")

    def query_ip(self, qry):
        # Check if cloudflare ip
        print(colored.stylize("\n--[ Using Cloudflare? ]--", colored.attr("bold")))
        if self.cflare_results(qry):
            logger.info("Cloudflare IP: Yes")
        else:
            logger.info("Cloudflare IP: No")

        print(colored.stylize("\n--[ Querying DNSBL Lists ]--", colored.attr("bold")))
        self.dnsbl_mapper()
        self.spamhaus_ipbl_worker()
        print(colored.stylize("\n--[ Querying IP Blacklists ]--", colored.attr("bold")))
        self.blacklist_ipbl_worker()
