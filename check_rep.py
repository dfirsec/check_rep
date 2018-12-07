#!/usr/bin/env python3

import random
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import dns.resolver
import requests
from clint.textui import colored

from feeds import DNSBL_LISTS, DOM_LISTS, IP_LISTS

__author__ = "DFIRSec"
__description__ = "Domain and IP Reputation Checker"
__version__ = "1.0.2"


if len(sys.argv) != 2:
    print("\n[-] Usage: check_rep.py 'ip address' or 'domain'\n")
    sys.exit(1)
else:
    QRY = sys.argv[1]


# ---[ Regex Parser ]-------------------------------
def regex(ioc_type):
    pattern = dict(
        ip_addr=r"((?:(?:[12]\d?\d?|[1-9]\d|[1-9])(?:\[\.\]|\.)){3}(?:[12]\d?\d?|[\d+]{1,2}))",
        domain=r"([A-Za-z0-9]+(?:[\-|\.][A-Za-z0-9]+)*(?:\[\.\]|\.)(?:\w{2,5}))"
    )

    try:
        pattern = re.compile(pattern[ioc_type])
    except re.error:
        print("[!] Invalid input specified.")
        sys.exit(0)

    return pattern


# ---[ Common User-Agents ]-------------------------------
def headers():
    ua_dict = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
        "Mozilla/5.0 (X11; Linux i686; rv:30.0) Gecko/20100101 Firefox/42.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.38 Safari/537.36",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
    ]
    use_headers = {
        'user-agent': random.choice(ua_dict)
    }
    return use_headers


# ---[ Query OpenSource DNSBL_lists ]-------------------------------
def blklst_qry(blacklist):
    try:
        req = requests.get(blacklist, headers=headers(), timeout=5)
        req.raise_for_status()
        req.encoding = 'utf-8'
        match = re.findall(QRY, req.text)
        if match:
            print(colored.red(f" [*] POSITIVE HIT: {QRY} --> {blacklist}"))

    except requests.exceptions.Timeout:
        print(colored.yellow(
            f" [-] WARNING: Timeout exceeded for {blacklist}"))
    except requests.exceptions.HTTPError as err:
        print(colored.yellow(f" [-] WARNING: {err}"))
    except requests.exceptions.ConnectionError as err:
        print(colored.yellow(f" [-] WARNING: Error Connecting: {err}"))
    except requests.exceptions.RequestException as err:
        print(colored.yellow(f" [-] WARNING: Fatal Action Occurred {err}"))


# ---[ Query DNSBL Lists ]-------------------------------
def dnsbl_qry(blacklist):
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.timeout = 5
        dns_resolver.lifetime = 5
        if regex(ioc_type='ip_addr').findall(QRY):
            query = '.'.join(reversed(str(QRY).split("."))) + "." + blacklist
        elif regex(ioc_type='domain').findall(QRY):
            query = '.'.join(str(QRY).split(".")) + "." + blacklist
        answers = dns_resolver.query(query, "A")
        answer_txt = dns_resolver.query(query, 'TXT')
        print(colored.red(f" [*] POSITIVE HIT: {QRY} --> {blacklist} {answers[0]} {answer_txt[0]}"))

    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.Timeout:
        print(colored.yellow(f' [-] WARNING: Timeout querying {blacklist}'))
    except dns.resolver.NoNameservers:
        print(colored.yellow(f' [-] WARNING: No name servers for {blacklist}'))
    except dns.resolver.NoAnswer:
        print(colored.yellow(f' [-] WARNING: No answer for {blacklist}'))


def main():
    with ThreadPoolExecutor() as exec_dnsbl:
        dnsbl_func = partial(dnsbl_qry)  # -> Pass to dnsbl_qry function
        print(colored.cyan("\n--[ Querying Spam Lists ]--"))
        exec_dnsbl.map(dnsbl_func, DNSBL_LISTS)

    with ThreadPoolExecutor() as exec_blklst:
        blklst_func = partial(blklst_qry)  # -> Pass to blklst_qry function
        # if ip address, query ip list
        if regex(ioc_type='ip_addr').findall(QRY):
            print(colored.cyan("\n--[ Querying IP Lists ]--"))
            exec_blklst.map(blklst_func, IP_LISTS)
        # if domain, query domain list
        elif regex(ioc_type='domain').findall(QRY):
            print(colored.cyan("\n--[ Querying Domain Lists ]--"))
            exec_blklst.map(blklst_func, DOM_LISTS)


if __name__ == "__main__":
    main()
