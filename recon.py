#!/usr/bin/env python3

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


# =================================================
# FILES
# =================================================

WORK_DIR = Path("work")

ROOT_DOMAINS_FILE = WORK_DIR / "root_domains.txt"
INPUT_HOSTS_FILE = WORK_DIR / "input_hosts.txt"

SUBFINDER_FILE = WORK_DIR / "subfinder.txt"
ALL_HOSTS_FILE = WORK_DIR / "all_hosts.txt"

DNSX_FILE = WORK_DIR / "dnsx.jsonl"
ALIVE_FILE = WORK_DIR / "alive.txt"

HTTPX_FILE = WORK_DIR / "httpx.jsonl"

CSV_FILE = WORK_DIR / "report.csv"


# =================================================
# UTILS
# =================================================

def check_binary(binary):

    if shutil.which(binary) is None:
        print(f"[!] Brak programu: {binary}")
        sys.exit(1)



def save_list(filename, values):

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        for value in sorted(values):
            f.write(value + "\n")



def load_list(filename):

    if not filename.exists():
        return set()

    with open(
        filename,
        encoding="utf-8"
    ) as f:

        return {
            line.strip()
            for line in f
            if line.strip()
        }



# =================================================
# SUBFINDER
# =================================================

def run_subfinder():

    if SUBFINDER_FILE.exists():

        print("[+] subfinder.txt istnieje - pomijam")

        return


    print("[*] Uruchamiam subfinder")


    cmd = [

        "subfinder",

        "-silent",

        "-all",

        "-dL",
        str(ROOT_DOMAINS_FILE),

        "-o",
        str(SUBFINDER_FILE)
    ]


    result = subprocess.run(cmd)


    if result.returncode != 0:

        raise RuntimeError(
            "subfinder zakończył się błędem"
        )


    print("[+] subfinder zakończony")



# =================================================
# MERGE HOSTS
# =================================================

def merge_hosts():

    if ALL_HOSTS_FILE.exists():

        print("[+] all_hosts.txt istnieje - pomijam")

        return


    print("[*] Łączenie hostów")


    hosts = set()


    hosts.update(
        load_list(INPUT_HOSTS_FILE)
    )


    hosts.update(
        load_list(SUBFINDER_FILE)
    )


    save_list(
        ALL_HOSTS_FILE,
        hosts
    )


    print(
        f"[+] Wszystkich hostów: {len(hosts)}"
    )



# =================================================
# DNSX
# =================================================

def run_dnsx():

    if DNSX_FILE.exists():

        print("[+] dnsx.jsonl istnieje - pomijam")

        return


    print("[*] Uruchamiam dnsx")


    cmd = [

        "dnsx",

        "-l",
        str(ALL_HOSTS_FILE),

        "-json",

        "-resp",

        "-silent",

        "-o",
        str(DNSX_FILE)
    ]


    result = subprocess.run(cmd)


    if result.returncode != 0:

        raise RuntimeError(
            "dnsx zakończył się błędem"
        )


    print("[+] dnsx zakończony")



# =================================================
# ALIVE
# =================================================

def create_alive_file():

    if ALIVE_FILE.exists():

        print("[+] alive.txt istnieje - pomijam")

        return


    alive = set()


    with open(
        DNSX_FILE,
        encoding="utf-8"
    ) as f:


        for line in f:

            try:

                data = json.loads(line)

                host = data.get("host")


                if host:

                    alive.add(host)


            except Exception:

                pass



    save_list(
        ALIVE_FILE,
        alive
    )


    print(
        f"[+] DNS alive: {len(alive)}"
    )



# =================================================
# HTTPX
# =================================================

def run_httpx():

    if HTTPX_FILE.exists():

        print("[+] httpx.jsonl istnieje - pomijam")

        return


    print("[*] Uruchamiam httpx")


    cmd = [

        "httpx",

        "-l",
        str(ALIVE_FILE),

        "-json",

        "-silent",

        "-title",

        "-status-code",

        "-location",

        "-web-server",

        "-tech-detect",

        "-ip",

        "-cname",

        "-cdn",

        "-favicon",

        "-threads",
        "100",

        "-timeout",
        "10",

        "-o",
        str(HTTPX_FILE)

    ]


    result = subprocess.run(cmd)


    if result.returncode != 0:

        raise RuntimeError(
            "httpx zakończył się błędem"
        )


    print("[+] httpx zakończony")



# =================================================
# HOST DATABASE
# =================================================

class HostDatabase:


    def __init__(self):

        self.hosts = defaultdict(
            lambda: {

                "domain": "",

                "type": "",

                "source": set(),

                "dns": False,

                "ip": [],

                "cname": [],

                "http": False,

                "https": False,

                "status_code": "",

                "title": "",

                "redirect": False,

                "redirect_to": "",

                "server": "",

                "tech": [],

                "archive": "",

                "content_length": "",

                "cdn": "",

                "favicon_hash": ""

            }
        )



    def add_host(
        self,
        host,
        source
    ):

        self.hosts[host]["domain"] = host

        self.hosts[host]["source"].add(
            source
        )



    def load_file(
        self,
        filename,
        source
    ):

        for host in load_list(filename):

            self.add_host(
                host,
                source
            )



    def load_dnsx(self):

        if not DNSX_FILE.exists():
            return


        with open(
            DNSX_FILE,
            encoding="utf-8"
        ) as f:


            for line in f:

                try:

                    data = json.loads(line)

                    host = data.get(
                        "host"
                    )


                    if not host:
                        continue


                    self.add_host(
                        host,
                        "dnsx"
                    )


                    entry = self.hosts[host]


                    entry["dns"] = True

                    entry["ip"] = data.get(
                        "a",
                        []
                    )

                    entry["cname"] = data.get(
                        "cname",
                        []
                    )


                except Exception:

                    pass



    def load_httpx(self):

        if not HTTPX_FILE.exists():
            return


        with open(
            HTTPX_FILE,
            encoding="utf-8"
        ) as f:


            for line in f:

                try:

                    data = json.loads(line)


                    host = data.get(
                        "host"
                    )


                    if not host:
                        continue



                    self.add_host(
                        host,
                        "httpx"
                    )


                    entry = self.hosts[host]


                    url = data.get(
                        "url",
                        ""
                    )


                    if url.startswith(
                        "https://"
                    ):

                        entry["https"] = True


                    if url.startswith(
                        "http://"
                    ):

                        entry["http"] = True



                    entry["status_code"] = data.get(
                        "status_code",
                        ""
                    )


                    entry["title"] = data.get(
                        "title",
                        ""
                    )


                    entry["server"] = data.get(
                        "webserver",
                        ""
                    )


                    entry["redirect_to"] = data.get(
                        "location",
                        ""
                    )


                    if entry["redirect_to"]:

                        entry["redirect"] = True



                    entry["tech"] = data.get(
                        "tech",
                        []
                    )


                    entry["cdn"] = data.get(
                        "cdn",
                        ""
                    )


                    entry["favicon_hash"] = data.get(
                        "favicon_hash",
                        ""
                    )


                except Exception:

                    pass



    def export_csv(self):

        fields = [

            "domain",

            "type",

            "source",

            "dns",

            "ip",

            "cname",

            "http",

            "https",

            "status_code",

            "title",

            "redirect",

            "redirect_to",

            "server",

            "tech",

            "archive",

            "content_length",

            "cdn",

            "favicon_hash"

        ]



        with open(
            CSV_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as f:


            writer = csv.DictWriter(
                f,
                fieldnames=fields
            )


            writer.writeheader()



            for host, data in sorted(
                self.hosts.items()
            ):


                row = data.copy()


                row["source"] = ",".join(
                    row["source"]
                )

                row["ip"] = ",".join(
                    row["ip"]
                )

                row["cname"] = ",".join(
                    row["cname"]
                )

                row["tech"] = ",".join(
                    row["tech"]
                )


                writer.writerow(row)



        print(
            f"[+] CSV zapisany: {CSV_FILE}"
        )



# =================================================
# MAIN
# =================================================

def main():

    parser = argparse.ArgumentParser(
        description=
        "Recon pipeline: subfinder + dnsx + httpx"
    )


    parser.add_argument(
        "input",
        help="plik wejściowy domen"
    )


    parser.add_argument(
        "-o",
        "--output",
        help="plik wynikowy"
    )


    args = parser.parse_args()



    for binary in [

        "subfinder",

        "dnsx",

        "httpx"

    ]:

        check_binary(binary)



    WORK_DIR.mkdir(
        exist_ok=True
    )


    run_subfinder()

    merge_hosts()

    run_dnsx()

    create_alive_file()

    run_httpx()



    print("[*] Budowanie bazy danych")


    db = HostDatabase()


    db.load_file(
        INPUT_HOSTS_FILE,
        "input"
    )


    db.load_file(
        SUBFINDER_FILE,
        "subfinder"
    )


    db.load_dnsx()

    db.load_httpx()


    db.export_csv()



    print()
    print("==============================")
    print(" GOTOWE")
    print("==============================")
    print(
        f"HOSTS: {len(db.hosts)}"
    )
    print(
        f"CSV: {CSV_FILE}"
    )
    print("==============================")



if __name__ == "__main__":

    main()
