import json
import sys
from http.client import responses

import requests

from core.utils import Helpers, logger

helpers = Helpers()


class VirusTotalChk:
    """https://developers.virustotal.com/v3.0/reference"""

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

        if api_key is None:
            raise SystemExit("Verify that you have provided your API key.")

    def vt_connect(self, url):
        """VirusTotal Connection"""
        try:
            resp = requests.get(url, headers=self.headers, timeout=5)
        except requests.exceptions.Timeout:
            logger.warning(f"[timeout] {url}")
        except requests.exceptions.HTTPError as err:
            logger.error(f"[error] {err}")
        except requests.exceptions.ConnectionError as err:
            logger.error(f"[error] {err}")
        except requests.exceptions.RequestException as err:
            logger.critical(f"[critical] {err}")
        else:
            resp.encoding = "utf-8"
            if resp.status_code == 401:
                sys.exit("[error] Verify that you have provided a valid API key.")
            if resp.status_code != 200:
                print(f"[error] {resp.status_code} {responses[resp.status_code]}")  # nopep8
            else:
                return resp.json()
        return None

    def vt_run(self, scan_type, qry):
        url = f"{self.base_url}/{scan_type}/{qry}"
        data = json.dumps(self.vt_connect(url))
        if json_resp := json.loads(data):
            good = 0
            bad = 0
            try:
                results = json_resp["data"]["attributes"]
            except AttributeError:
                pass
            else:
                if results:
                    for engine, result in results["last_analysis_results"].items():
                        if result["category"] == "malicious":
                            bad += 1
                            logger.error(f"\u2718 {engine}: {result['category'].upper()}")
                        else:
                            good += 1
                    if bad == 0:
                        logger.success(f"\u2714 {good} engines deemed '{qry}' as harmless\n")  # nopep8
                    else:
                        logger.info(f"{bad} engines deemed '{qry}' as malicious\n")
