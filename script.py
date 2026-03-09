import sys
import os
import subprocess
import datetime
import requests
from utilities import *

class Scanner:
    def __init__(self, target):
        self.target = target

    # +---------- MANAGE DEPENDENCIES TOOLS -----------+

    def create_repositories(self):
        """
        Creates needed repositories
        """
        user = os.getenv('SUDO_USER')

        # Create target directory
        base_path = os.path.join("/home", user, "Desktop")
        self.target_directory = os.path.join(base_path, self.target)
        if not os.path.exists(self.target_directory):
            os.mkdir(self.target_directory)
        
        # Create scan directory inside target directory
        today = datetime.datetime.today().strftime("%Y%m%d")
        self.scan_directory_path = os.path.join(self.target_directory, today)
        if not os.path.exists(self.scan_directory_path):
            os.mkdir(self.scan_directory_path)

        # Create lists directory inside target directory
        self.lists_path = os.path.join(self.target_directory, "lists")
        already_existed = True
        if not os.path.exists(self.lists_path):
            os.mkdir(self.lists_path)
            already_existed = False
        
        return already_existed 

    def obtain_valid_resolvers(self):
        """
        Get valid resolvers and save is in the valid_resolvers path
        """
        subprocess.run([
            "resolvalid",
            "-o",  self.valid_resolvers_path
        ], check=True)

    def obtain_dns_wordlist(self):
        """
        Get an updated dns wordlist
        """
        # Long list: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt
        result = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt")

        with open(self.wordlist_path, "w") as file:
            file.write(str(result.text))


    # +------------ FOOTPRINTING SCAN TOOLS ---------------+

    def run_shuffledns(self):
        """
        Executes shuffledns and saves its results.
        """
        subprocess.run([
            "shuffledns",
            "-mode", "bruteforce",
            "-t", "300",
            "-d", self.target,
            "-w", self.wordlist_path,
            "-r", self.valid_resolvers_path,
            "-mcmd", "-s 3500",
            "-o", os.path.join(self.scan_directory_path, "shuffledns_output.txt"),
            "-silent"
            ],
            check=True)
            
    def run_analyticsrelationships(self):
        """
        Executes analyticsrelationships tools and saves its results.
        """
        analyticsrelationships_results = subprocess.run([
                                                        "analyticsrelationships", 
                                                        "--url",
                                                        self.target],
                                                        capture_output=True,
                                                        text=True,
                                                        check=True
                                                        )
        
        write_results_file(analyticsrelationships_results.stdout, os.path.join(self.scan_directory_path, "analyticsreltionships_output.txt"))

    def run_cero(self):
        """
        Runs cero and saves its output
        """
        with open(os.path.join(self.scan_directory_path, "shuffledns_output.txt"), "r") as file:
            targets = [line.strip() for line in file if line.strip()]

        cero_results = subprocess.run([
                                        "cero", 
                                        "-d"] + targets,
                                        capture_output=True,
                                        text=True,
                                        check=True
                                        )
        
        write_results_file(cero_results.stdout, os.path.join(self.scan_directory_path, "cero_output.txt"))

    def run_ctfr(self):
        """
        Runs ctfr and saves its output
        """
        cero_results = subprocess.run([
                                        "ctfr", 
                                        "-d", self.target],
                                        capture_output=True,
                                        text=True,
                                        check=True
                                        )
        
        write_results_file(cero_results.stdout, os.path.join(self.scan_directory_path, "ctfr_output.txt"))

    def run_gau(self):
        """
        Runs gau and saves its output
        """
        subprocess.run([
                        "gau", 
                        "--threads", "5",
                        self.target,
                        "--o", os.path.join(self.scan_directory_path, "gau_output.txt")],
                        capture_output=True,
                        text=True,
                        check=True
                        )


    # +------------ PROCESS RESULT FILES ---------------+

    def gather_all_subdomains(self):
        all_files = os.listdir(self.scan_directory_path)
        txt_files = filter(lambda x: x[-4:] == ".txt", all_files)

        all_subdomains = []
        for file in txt_files:
            with open(os.path.join(self.scan_directory_path, file), "r") as f:
                all_subdomains.append(f.readlines())

        with open(os.path.join(self.scan_directory_path, "all_subdomains_unfiltered.txt"), "w") as f:
            for lst in all_subdomains:
                f.writelines(lst)

    def filter_unique_subdomains(self):
        with open(os.path.join(self.scan_directory_path, "all_subdomains_unfiltered.txt"), "r") as f:
            all_subdomains = [line.strip() for line in f]
        
        
        # Filter out domains out of scope
        all_targets = [domain for domain in all_subdomains if domain.lower().endswith("." + self.target)]
        
        # Remove http and https
        clean_targets = []
        for target in all_targets:
            target = target.strip()

            if target.startswith("https://"):
                clean_targets.append(target[7:])
            elif target.startswith("http://"):
                clean_targets.append(target[6:])
            elif target.startswith("[-]"):
                clean_targets.append(target[3:].lstrip())
            elif target.startswith("*."):
                pass
            else:
                clean_targets.append(target)
        
        # Remove duplicates
        clean_targets = set(clean_targets)

        self.unique_domains_path = os.path.join(self.scan_directory_path, "all_targets_filtered.txt")

        with open(self.unique_domains_path, "w") as f:
            for line in clean_targets:
                f.write(line + "\n")
        

    # +----------- FINGERPRINTING TOOLS --------------+

    def run_httpx(self):
        self.alive_domains_path = os.path.join(self.scan_directory_path, "alive_domains.txt")
        subprocess.run([
            "httpx",
            "-l", self.unique_domains_path,
            "-o", self.alive_domains_path,
            "-silent"
        ])
    
    def run_masscan(self):
        """
        Runs basic masscan scan and saves its output
        """

        subprocess.run(["masscan",
                        "-p21,22,80,443,8080",
                        "-iL", self.alive_ips_path,
                        "-oL", os.path.join(self.scan_directory_path, "masscan_output.txt")], 
                       check=True)
        

    # +----------- ORQUESTRATORS --------------+

    def manage_dependencies(self):
        """
        Creates all repositories and obtains needed external files
        """
        tools = [
            ("Obtain valid resolvers", self.obtain_valid_resolvers),
            ("Obtain DNS wordlists", self.obtain_dns_wordlist)
        ]
        
        lists_already_existed = self.create_repositories()
        self.valid_resolvers_path = os.path.join(self.lists_path, "valid_resolvers.txt")
        self.wordlist_path = os.path.join(self.lists_path, "dns_wordlists.txt")
        if not lists_already_existed:
            for name, tool in tools:
                try:
                    print(f"Executing {name}")
                    tool()
                    print(f"Executed {name}")
                except Exception as e:
                    print(f"[ERROR] {name} failed: {e}")
            
    def run_footprinting_scan(self):
        """
        Runs all footprinting scan tools
        """
        tools = [
        ("ShuffleDNS", self.run_shuffledns),
        ("AnalyticsRelationships", self.run_analyticsrelationships),
        ("Cero", self.run_cero),
        ("CTFR", self.run_ctfr),
        ("gau", self.run_gau)
        ]

        for name, tool in tools:
            try:
                print(f"Executing {name}")
                tool()
                print(f"Executed {name}")
            except Exception as e:
                print(f"[ERROR] {name} failed: {e}")
    
    def process_all_subdomains(self):
        """
        Processes all subdomains obtained through different footprinting techniques and provides a final all_subdomains_unfiltered.txt file.
        """
        tools = [
            ("Gather all subdomains", self.gather_all_subdomains),
            ("Obtain final list without duplicates", self.filter_unique_subdomains)
        ]
        for name, tool in tools:
            try:
                print(f"Executing {name}")
                tool()
                print(f"Executed {name}")
            except Exception as e:
                print(f"[ERROR] {name} failed: {e}")
        
    def process_subdomains_to_ip(self):
        with open(self.alive_domains_path, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
        
        ips = domains_to_ip(domains)
        self.alive_ips_path = os.path.join(self.scan_directory_path, "alive_ips.txt")
        with open(self.alive_domains_path, "w") as f:
            for line in ips:
                f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1] == "update":
        pass
    elif sys.argv[1] == "debug":
        pass
    else:
        scanner = Scanner(sys.argv[1])
        scanner.manage_dependencies()
        scanner.run_footprinting_scan()
        scanner.process_all_subdomains()
        scanner.run_httpx()
        scanner.process_subdomains_to_ip()
        scanner.run_masscan()