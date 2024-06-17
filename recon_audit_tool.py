#!/usr/bin/python3

import whois
import requests as req
from ipwhois import IPWhois
import socket
import os
import dns.resolver
import dns.query
from email_crawler import EmailCrawler
from Wappalyzer import Wappalyzer, WebPage
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import concurrent.futures
from colorama import init, Fore, Style
import datetime
import shutil
import csv
import html
from weasyprint import HTML
import re
import subprocess








######################################################################################################################
######################################################################################################################

# ██████   █████  ███    ██ ███    ██ ███████ ██████  
# ██   ██ ██   ██ ████   ██ ████   ██ ██      ██   ██ 
# ██████  ███████ ██ ██  ██ ██ ██  ██ █████   ██████  
# ██   ██ ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ 
# ██████  ██   ██ ██   ████ ██   ████ ███████ ██   ██ 
                                                    

######################################################################################################################
######################################################################################################################



# Initialize colorama
init(autoreset=True)


# Global Variables
# Global variable to store the target IP address or domain
global_target = None

def set_global_target():
    global global_target
    target = input("\n\n[+] Enter IP address or domain for reconnaissance: ").strip()
    global_target = target
    
    # Calling the function to create folder structure for the target
    create_folder_structure(global_target)

def banner():
     banner = '''\033[92m

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗ ██████╗ ██████╗     ██╗   ██╗ ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██╔═══██╗██╔══██╗    ██║   ██║███║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████║██║   ██║██║  ██║██║   ██║   ██║   ██║██████╔╝    ██║   ██║╚██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔══██║██║   ██║██║  ██║██║   ██║   ██║   ██║██╔══██╗    ╚██╗ ██╔╝ ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║  ██║╚██████╔╝██████╔╝██║   ██║   ╚██████╔╝██║  ██║     ╚████╔╝  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝      ╚═══╝   ╚═╝
    \033[0m
    '''
     print(banner)





######################################################################################################################
######################################################################################################################


# ██████   █████  ███████ ███████ ██ ██    ██ ███████     ██████  ███████  ██████  ██████  ███    ██ 
# ██   ██ ██   ██ ██      ██      ██ ██    ██ ██          ██   ██ ██      ██      ██    ██ ████   ██ 
# ██████  ███████ ███████ ███████ ██ ██    ██ █████       ██████  █████   ██      ██    ██ ██ ██  ██ 
# ██      ██   ██      ██      ██ ██  ██  ██  ██          ██   ██ ██      ██      ██    ██ ██  ██ ██ 
# ██      ██   ██ ███████ ███████ ██   ████   ███████     ██   ██ ███████  ██████  ██████  ██   ████ 


######################################################################################################################
######################################################################################################################



# Passive Recon option menu
def display_passive_recon_options():
    recon_types = {
        1: 'Whois Lookup',
        2: 'Website Header Lookup',
        3: 'Target ASN and IP Range Lookup',
        4: 'DNS Lookup (Single IP/Multiple IP)',
        5: 'Mail Server Lookup (MX Records)',
        6: 'Name Server Lookup',
        7: 'Email Finder',
        8: 'Back',
        # Add more recon types as needed
    }
    
    print("[*] Passive Recon Options:\n")
    for option, recon_type in recon_types.items():
        print(f"[{option}] {recon_type}")


# Perform Whois Lookup

def perform_whois_lookup(domain):
    
    target_folder = domain  # Define the target folder within the function

    
    try:
        # Perform WHOIS lookup
        whois_info = whois.whois(domain)

        # Prepare the WHOIS information as a string
        whois_details = []
        whois_details.append(f"WHOIS information for {domain}:\n")

        if isinstance(whois_info.domain_name, list):
            whois_details.append(f"Domain Name: {', '.join(whois_info.domain_name)}")
        else:
            whois_details.append(f"Domain Name: {whois_info.domain_name}")

        whois_details.append(f"Registrar: {whois_info.registrar}")
        whois_details.append(f"WHOIS Server: {whois_info.whois_server}")
        whois_details.append(f"Updated Date: {whois_info.last_updated}")
        whois_details.append(f"Creation Date: {whois_info.creation_date}")
        whois_details.append(f"Expiration Date: {whois_info.expiration_date}")
        whois_details.append(f"Name Servers: {', '.join(whois_info.name_servers)}")

        if whois_info.emails:
            whois_details.append(f"Contact Emails: {', '.join(whois_info.emails)}")
        if whois_info.address:
            whois_details.append(f"Contact Address: {whois_info.address}")

        # Print WHOIS information
        for detail in whois_details:
            print(detail)

        # Ensure the Passive Recon folder exists
        passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
        if not os.path.exists(passive_recon_folder):
            os.makedirs(passive_recon_folder)

        # Write WHOIS information to a file
        whois_file_path = os.path.join(passive_recon_folder, f"{domain}_whois.txt")
        with open(whois_file_path, 'w') as file:
            file.write('\n'.join(whois_details))

        print(f"\n[+] WHOIS information saved to {whois_file_path}\n")
        

    except Exception as e:
        print(f"\n[-] WHOIS information not found: {e}")


# Security Header Analysis Module

def security_header_analysis(url):
    
    target_folder = url
    
    try:
        resp = req.get("https://" + url)
        pStatus = str(resp.status_code)
        hInfo = resp.headers
        eType = str(resp.encoding)

        # Prepare content for request headers
        request_headers_content = f"\nTARGET REQUEST HEADERS FOR: {url}\n\n"
        request_headers_content += "---------------------------------------------------------------------------\n\n"
        request_headers_content += f"Page Status: {pStatus}\n"
        request_headers_content += f"Encoding Type: {eType}\n"

        # Prepare content for response headers
        response_headers_content = f"\nTARGET RESPONSE HEADERS FOR: {url}\n\n"
        response_headers_content += "---------------------------------------------------------------------------\n\n"
        for key, value in hInfo.items():
            response_headers_content += f"{key}: {value}\n"

        # Prepare content for security evaluation
        security_evaluation_content = f"\nTARGET SECURITY HEADERS FOR: {url}\n"
        security_evaluation_content += "-----------------------------------------------------------------------\n\n"

        # List of security headers to check
        security_headers = [
            ('Strict-Transport-Security', 'strict-transport-security'),
            ('Content-Security-Policy', 'content-security-policy'),
            ('Access-Control-Allow-Origin', 'access-control-allow-origin'),
            ('X-Frame-Options', 'x-frame-options'),
            ('X-Content-Type-Options', 'x-content-type-options'),
            ('Cross-Origin-Resource-Policy', 'cross-origin-resource-policy'),
            ('Referrer-Policy', 'referrer-policy'),
            ('Permissions-Policy', 'permissions-policy'),
            ('Clear-Site-Data', 'clear-site-data'),
            ('X-XSS-Protection', 'x-xss-protection'),
            ('Expect-CT', 'expect-ct'),
            ('Server', 'server'),
            ('X-Powered-By', 'x-powered-by')
        ]

        for header, alt_header in security_headers:
            if header in hInfo or alt_header in hInfo:
                security_evaluation_content += f"{Fore.GREEN}\n[+] Security {header} Header: SET{Style.RESET_ALL}\n"
            else:
                security_evaluation_content += f"{Fore.RED}\n[-] Security {header} Header: NOT SET{Style.RESET_ALL}\n"
                security_evaluation_content += f"{Fore.YELLOW}   [INFO] {header} MISCONFIGURATION FOUND{Style.RESET_ALL}\n"

        # Print contents to console
        print(request_headers_content)
        print(response_headers_content)
        print(security_evaluation_content)

        # Ensure the Passive Recon folder exists
        passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
        if not os.path.exists(passive_recon_folder):
            os.makedirs(passive_recon_folder)

        # Write request headers to a file
        request_headers_file_path = os.path.join(passive_recon_folder, f"{url}_request_headers.txt")
        with open(request_headers_file_path, 'w') as file:
            file.write(request_headers_content)

        # Write response headers to a file
        response_headers_file_path = os.path.join(passive_recon_folder, f"{url}_response_headers.txt")
        with open(response_headers_file_path, 'w') as file:
            file.write(response_headers_content)

        # Write security evaluation to a file
        security_evaluation_file_path = os.path.join(passive_recon_folder, f"{url}_security_evaluation.txt")
        with open(security_evaluation_file_path, 'w') as file:
            file.write(security_evaluation_content)

        print(f"\n[+] Request headers saved to {request_headers_file_path}")
        print(f"\n[+] Response headers saved to {response_headers_file_path}")
        print(f"\n[+] Security evaluation saved to {security_evaluation_file_path}\n\n")

    except req.exceptions.RequestException as e:
        print(f"\n[!] Error occurred while fetching headers: {e}")


# ASN and IP Range lookup Module

# Getting the ip address of a domain
def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error: {e}")
        return None

def get_asn_info(target):
    
    target_folder = target

    try:
        ipwhois = IPWhois(get_ip_address(target))
        result = ipwhois.lookup_rdap(depth=1)
        
        asn = result['asn']
        asn_description = result['asn_description']
        ip_ranges = result['network']['cidr']

        # Prepare the content to be written to the file
        asn_info_content = f"\nASN: {asn}\n"
        asn_info_content += f"ASN Description: {asn_description}\n"
        asn_info_content += "IP Ranges:\n"
        for ip_range in ip_ranges:
            asn_info_content += f"{ip_range}"
        asn_info_content += "\n"

        # Print the content to the console
        print(asn_info_content)

        # Ensure the Passive Recon folder exists
        passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
        if not os.path.exists(passive_recon_folder):
            os.makedirs(passive_recon_folder)

        # Write ASN info to a file
        asn_info_file_path = os.path.join(passive_recon_folder, f"{target}_asn_info.txt")
        with open(asn_info_file_path, 'w') as file:
            file.write(asn_info_content)

        print(f"\n[+] ASN information saved to {asn_info_file_path}\n\n")

    except Exception as e:
        print(f"\n[!] Error: {e}")



# DNS Lookup Module

def dns_lookup_single(domain):
    target_folder = domain
    
    
    try:
        ip_address = socket.gethostbyname(domain)
        print(f'\n[+] IP address of {domain}: {ip_address}\n')
        
        # Prepare the content to be written to the file
        dns_info_content = f"Domain: {domain}\nIP Address: {ip_address}\n"

        # Ensure the Passive Recon folder exists
        passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
        if not os.path.exists(passive_recon_folder):
            os.makedirs(passive_recon_folder)

        # Write DNS info to a file
        dns_info_file_path = os.path.join(passive_recon_folder, f"{domain}_dns_info.txt")
        with open(dns_info_file_path, 'w') as file:
            file.write(dns_info_content)

        print(f"\n[+] DNS information saved to {dns_info_file_path}\n\n")

    except socket.gaierror as e:
        print(f"\n[!] Error: {e}")
    

def dns_lookup_multiple(domain):
    
    target_folder = domain
    
    try:
        _, _, ip_addresses = socket.gethostbyname_ex(domain)
        print(f'\n[+] All IP addresses of {domain}:\n')
        for ip in ip_addresses:
            print(f'- {ip}')
        
        # Prepare the content to be written to the file
        dns_info_content = f"All IP addresses of {domain}:\n"
        for ip in ip_addresses:
            dns_info_content += f"- {ip}\n"

        # Ensure the Passive Recon folder exists
        passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
        if not os.path.exists(passive_recon_folder):
            os.makedirs(passive_recon_folder)

        # Write DNS info to a file
        dns_info_file_path = os.path.join(passive_recon_folder, f"{domain}_dns_info_all.txt")
        with open(dns_info_file_path, 'w') as file:
            file.write(dns_info_content)

        print(f"\n[+] DNS information saved to {dns_info_file_path}\n\n")

    except socket.gaierror as e:
        print(f"\n[!] Error: {e}")


def dns_lookup(domain):
    # Function to perform DNS lookup based on user input
    while True:

        os.system('cls' if os.name == 'nt' else 'clear')

        banner()

        print("\nChoose DNS lookup option:")
        print("[1] Single IP")
        print("[2] All IP addresses")
        print("[3] Back")

        choice = input("\n[+] Enter your choice(1-3): ").strip()
        
        if choice == '1':
            dns_lookup_single(domain)
            input("\n")
        elif choice == '2':
            dns_lookup_multiple(domain)
            input("\n")
        elif choice == '3':
            break
        else:
            print("\n[-] Invalid choice. Please enter 1, 2, or 3.\n")



# Mail Server Lookup

def mx_lookup(domain):
    
    target_folder = domain
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', raise_on_no_answer=False)
        
        # Prepare the content to be written to the file
        mx_info_content = f"Mail servers for {domain}:\n"
        for mx in mx_records:
            mx_info_content += f'- Priority {mx.preference}: {mx.exchange}\n'
        
        print("\n")
        print(mx_info_content)
        
        # Ensure the Passive Recon folder exists
        passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
        if not os.path.exists(passive_recon_folder):
            os.makedirs(passive_recon_folder)

        # Write MX info to a file
        mx_info_file_path = os.path.join(passive_recon_folder, f"{domain}_mx_info.txt")
        with open(mx_info_file_path, 'w') as file:
            file.write(mx_info_content)

        print(f"\n[+] MX records saved to {mx_info_file_path}\n\n")

    except dns.resolver.NoAnswer:
        print(f'\n[-] No MX records found for {domain}')
    except dns.resolver.NXDOMAIN:
        print(f'\n[-] The domain {domain} does not exist')
    except dns.resolver.Timeout:
        print(f'\n[-] Timeout querying MX records for {domain}')
    except Exception as e:
        print(f'\n[!] Error querying MX records for {domain}: {e}')



# Function to perform NS lookup
def ns_lookup(domain):
    
    target_folder = domain
    
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        
        # Prepare the content to be written to the file and printed
        ns_info_content = f"Nameservers for {domain}:\n"
        for ns in ns_records:
            ns_info_content += f'- {ns.target}\n'
            print(f'\n- {ns.target}\n')

        # Ensure the Passive Recon folder exists
        passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
        if not os.path.exists(passive_recon_folder):
            os.makedirs(passive_recon_folder)

        # Write NS info to a file
        ns_info_file_path = os.path.join(passive_recon_folder, f"{domain}_ns_info.txt")
        with open(ns_info_file_path, 'w') as file:
            file.write(ns_info_content)

        print(f"\n[+] NS records saved to {ns_info_file_path}\n\n")

    except dns.resolver.NoAnswer:
        print(f'\n[-] No NS records found for {domain}')
    except dns.resolver.NXDOMAIN:
        print(f'\n[-] The domain {domain} does not exist')
    except dns.resolver.Timeout:
        print(f'\n[-] Timeout querying NS records for {domain}')
    except Exception as e:
        print(f'\n[!] Error querying NS records for {domain}: {e}')


# Email Finder 

def find_emails(domain):
    
    target_folder = domain
    try:
        emails = EmailCrawler("https://"+domain, max_pages=10)

        if emails:
            print(f"\n[+] Emails found for {domain}:\n`")
            emails.crawl()
        else:
            print(f"\n[-] No emails found for {domain}\n")
            
        # Assuming the CSV file already exists in the current directory
        rename_domain = domain.replace(".","_")
        csv_file_path = f"{rename_domain}.csv"

        if os.path.exists(csv_file_path):
            print(f"\n[+] CSV file found for {domain}\n")

            # Ensure the Passive Recon folder exists in the target folder
            passive_recon_folder = os.path.join(target_folder, 'Passive Recon')
            if not os.path.exists(passive_recon_folder):
                os.makedirs(passive_recon_folder)

            # Move the CSV file to the Passive Recon folder and rename it
            passive_recon_csv_path = os.path.join(passive_recon_folder, f"{domain}_emails.csv")
            shutil.move(csv_file_path, passive_recon_csv_path)
            print(f"\n[+] CSV file moved to Passive Recon folder: {passive_recon_csv_path}\n\n")

        else:
            print(f"\n[-] No CSV file found for {domain}\n\n")

    except Exception as e:
        print(f"\n[!] Error finding emails for {domain}: {e}\n")




# Passive Recon Modules

def passive_recon_module():
    global global_target
    target = global_target or input("\n[+] Enter IP address or domain for reconnaissance: ").strip()

    try:
        ip_address = get_ip_address(target)
        if ip_address:
            print(f"\n[+] Target IP Address: {ip_address}\n")
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')

                banner()
                display_passive_recon_options()
                choice = input("\n[+] Enter your passive recon choice (1-8): ").strip()

                if choice == '1':
                    perform_whois_lookup(target)
                
                elif choice == '2':
                    security_header_analysis(target if ip_address else f"http://{target}")
                
                elif choice == '3':
                    get_asn_info(target if ip_address else f"http://{target}")
                
                elif choice == '4':
                    dns_lookup(target)
                
                elif choice == '5':
                    mx_lookup(target)
                
                elif choice == '6':
                    ns_lookup(target)
                
                elif choice == '7':
                    find_emails(target)
                    
                elif choice == '8':
                    break
                
                else:
                    print("\n[-] Invalid choice. Please enter a number between 1 and 8.\n")
                
                cont = input("\n[?] Do you want to perform another passive recon action? (yes/no): ").strip().lower()
                if cont != 'yes':
                    break
        else:
            print("\n[!] Unable to resolve IP address or domain.\n")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        



######################################################################################################################
######################################################################################################################

#  █████╗  ██████╗████████╗██╗██╗   ██╗███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
# ██╔══██╗██╔════╝╚══██╔══╝██║██║   ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
# ███████║██║        ██║   ██║██║   ██║█████╗      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
# ██╔══██║██║        ██║   ██║╚██╗ ██╔╝██╔══╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
# ██║  ██║╚██████╗   ██║   ██║ ╚████╔╝ ███████╗    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
# ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══

######################################################################################################################
######################################################################################################################



# Active Recon option menu
def display_active_recon_options():
    recon_types = {
        1: 'Website Header Enumeration',
        2: 'Technology Stack Identification',
        3: 'Web Links/Meta Tags/Response Header Enumeration',
        4: 'Subdomain Enumeration',
        5: 'WAF Enumeration',
        6: 'Port Scanning',
        7: 'Back',
        # Add more recon types as needed
    }
    
    print("\n[+] Active Recon Options:\n")
    for option, recon_type in recon_types.items():
        print(f"[{option}] {recon_type}")




# Security Header Analysis Module
def website_header_analysis(url):
    
    target_folder = url
    
    try:
        resp = req.get("https://" + url)
        pStatus = str(resp.status_code)
        hInfo = resp.headers
        eType = str(resp.encoding)

        # Prepare content for request headers
        request_headers_content = f"\nTARGET REQUEST HEADERS FOR: {url}\n"
        request_headers_content += "---------------------------------------------------------------------------\n\n"
        request_headers_content += f"Page Status: {pStatus}\n"
        request_headers_content += f"Encoding Type: {eType}\n"

        # Prepare content for response headers
        response_headers_content = f"\nTARGET RESPONSE HEADERS FOR: {url}\n"
        response_headers_content += "--------------------------------------------------------------------------\n\n"
        for key, value in hInfo.items():
            response_headers_content += f"{key}: {value}\n"

        # Prepare content for security evaluation
        security_evaluation_content = f"\nTARGET SECURITY HEADERS FOR {url}\n"
        security_evaluation_content += "-----------------------------------------------------------------------\n\n"

        # List of security headers to check
        security_headers = [
            ('Strict-Transport-Security', 'strict-transport-security'),
            ('Content-Security-Policy', 'content-security-policy'),
            ('Access-Control-Allow-Origin', 'access-control-allow-origin'),
            ('X-Frame-Options', 'x-frame-options'),
            ('X-Content-Type-Options', 'x-content-type-options'),
            ('Cross-Origin-Resource-Policy', 'cross-origin-resource-policy'),
            ('Referrer-Policy', 'referrer-policy'),
            ('Permissions-Policy', 'permissions-policy'),
            ('Clear-Site-Data', 'clear-site-data'),
            ('X-XSS-Protection', 'x-xss-protection'),
            ('Expect-CT', 'expect-ct'),
            ('Server', 'server'),
            ('X-Powered-By', 'x-powered-by')
        ]

        for header, alt_header in security_headers:
            if header in hInfo or alt_header in hInfo:
                security_evaluation_content += f"{Fore.GREEN}\n[+] Security {header} Header: SET{Style.RESET_ALL}\n"
            else:
                security_evaluation_content += f"{Fore.RED}\n[-] Security {header} Header: NOT SET{Style.RESET_ALL}\n"
                security_evaluation_content += f"{Fore.YELLOW}   [INFO] {header} MISCONFIGURATION FOUND{Style.RESET_ALL}\n"

        # Print contents to console
        print("\n[+]"+request_headers_content)
        print("\n[+]"+response_headers_content)
        print("\n[+]"+security_evaluation_content)

        # Ensure the Passive Recon folder exists
        active_recon_folder = os.path.join(target_folder, 'Active Recon')
        if not os.path.exists(active_recon_folder):
            os.makedirs(active_recon_folder)

        # Write request headers to a file
        request_headers_file_path = os.path.join(active_recon_folder, f"{url}_request_headers.txt")
        with open(request_headers_file_path, 'w') as file:
            file.write(request_headers_content)

        # Write response headers to a file
        response_headers_file_path = os.path.join(active_recon_folder, f"{url}_response_headers.txt")
        with open(response_headers_file_path, 'w') as file:
            file.write(response_headers_content)

        # Write security evaluation to a file
        security_evaluation_file_path = os.path.join(active_recon_folder, f"{url}_security_evaluation.txt")
        with open(security_evaluation_file_path, 'w') as file:
            file.write(security_evaluation_content)

        print(f"\n[+] Request headers saved to {request_headers_file_path}")
        print(f"\n[+] Response headers saved to {response_headers_file_path}")
        print(f"\n[+] Security evaluation saved to {security_evaluation_file_path}\n\n")

    except req.exceptions.RequestException as e:
        print(f"\n[!] Error occurred while fetching headers: {e}")




# Function to identify technology stack using Wappalyzer
def identify_technology_stack(url):

    target_folder = url 
    
    try:
        # Initialize Wappalyzer
        wappalyzer = Wappalyzer.latest()

        # Fetch the webpage
        webpage = WebPage.new_from_url("http://"+url)

        # Analyze the webpage to detect technologies
        technologies = wappalyzer.analyze_with_versions_and_categories(webpage)

        # Prepare output
        output = f"\n[+] Technology stack for {url}:\n"
        for technology, details in technologies.items():
            categories = ', '.join(details.get('categories', []))
            versions = ', '.join(details.get('versions', [])) if details.get('versions') else 'N/A'
            output += f"- {technology} (Categories: {categories}, Versions: {versions})\n"

        # Print to console
        print("\n")
        print(output)

        active_recon_folder = os.path.join(target_folder, "Active Recon")

        # Create folders if they don't exist
        os.makedirs(active_recon_folder, exist_ok=True)

        # Write to file
        output_file_path = os.path.join(active_recon_folder, f"{url}_technology_stack.txt")
        with open(output_file_path, 'w') as file:
            file.write(output)
            
        
        print(f"\n[+] Technology stack information saved to {output_file_path}\n\n")

    except Exception as e:
        print(f"\n[-] Error identifying technology stack: {e}")



# Webiste Link/Meta Tags/Response Header enumeration module

def website_link_enumeration(url):
    
    # Define folder structure
    target_folder = url
    
    try:
        # Send a GET request to the URL
        response = requests.get("https://"+url)
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the HTML content of the page
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract all links on the page
            links = soup.find_all('a', href=True)
            
            # Print and prepare links output
            links_output = f"\n\n[+] Links found on {url}:\n\n"
            for link in links:
                links_output += f"{link['href']}\n"
            print(links_output)
            
            # Extract meta tags
            meta_tags = soup.find_all('meta')
            
            # Print and prepare meta tags output
            meta_tags_output = f"\n[+] Meta tags found on {url}:\n\n"
            for tag in meta_tags:
                meta_tags_output += f"{tag}\n"
            print(meta_tags_output)
            
            # Analyze response headers
            headers = response.headers
            
            # Print and prepare headers output
            headers_output = "\n[+] Response Headers:\n\n"
            for header, value in headers.items():
                headers_output += f"{header}: {value}\n"
            print(headers_output)
            

            active_recon_folder = os.path.join(target_folder, "Active Recon")
            
            # Create folders if they don't exist
            os.makedirs(active_recon_folder, exist_ok=True)
            
            # Write links to file
            links_file_path = os.path.join(active_recon_folder, f"{url}_active_links.txt")
            with open(links_file_path, 'w') as file:
                file.write(links_output)
            
            # Write meta tags to file
            meta_tags_file_path = os.path.join(active_recon_folder, f"{url}_meta_tags.txt")
            with open(meta_tags_file_path, 'w') as file:
                file.write(meta_tags_output)
            
            # Write headers to file
            headers_file_path = os.path.join(active_recon_folder, f"{url}_response_headers2.txt")
            with open(headers_file_path, 'w') as file:
                file.write(headers_output)
                
            
            print(f"\n[+] Active links saved to {links_file_path}")
            print(f"\n[+] Meta tags saved to {meta_tags_file_path}")
            print(f"\n[+] Headers saved to {headers_file_path}\n\n")
        
        else:
            print(f"\n[-] Failed to retrieve {url}. Status code: {response.status_code}")
    
    except requests.RequestException as e:
        print(f"\n[!] Error during request: {e}")




# Subdomain Enumeration
def gather_subdomains(domain):
    
    # Define folder structure
    target_folder = domain
    
    subdomains = []

    # List of common subdomain prefixes to check
    subdomain_prefixes = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm',
        'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum',
        'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
        'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
        'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
        'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host',
        'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
        'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4'
    ]

    
    active_recon_folder = os.path.join(target_folder, "Active Recon")

    # Create folders if they don't exist
    os.makedirs(active_recon_folder, exist_ok=True)

    subdomains_output = f"[+] Enumerating subdomains for {domain}...\n\n"

    # Perform DNS queries for each prefix
    print(f"\n[+] Enumerating subdomains for {domain}...\n\n")
    for prefix in subdomain_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for answer in answers:
                subdomains.append(subdomain)
                output_line = f"[$] Found subdomain: {subdomain} - {answer}\n"
                subdomains_output += output_line
                print(output_line, end="")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            continue
        except Exception as e:
            error_line = f"\n[!] Error querying {subdomain}: {e}\n"
            subdomains_output += error_line
            print(error_line, end="")

    # Write subdomains to file
    subdomains_file_path = os.path.join(active_recon_folder, f"{domain}_subdomains.txt")
    with open(subdomains_file_path, 'w') as file:
        file.write(subdomains_output)
        
    print(f"\n[+] Subdomains saved to {subdomains_file_path}\n\n")


# WAF Detection Function

def detect_waf(url):
    
    # Define folder structure
    target_folder = url
    
    print("\n[#] Please wait....\n")
    
    try:
        # Make a request to the web application
        response = requests.get("https://"+url)

        # List of known WAF headers and their associated WAF names
        waf_signatures = {
            'Server': {
                'cloudflare': 'Cloudflare',
                'AkamaiGHost': 'Akamai',
                'bigip': 'F5 BIG-IP',
                'Astra': 'Astra WAF',
            },
            'X-Sucuri-ID': 'Sucuri',
            'X-Firewall': 'Generic Firewall',
            'X-WAF-Status': 'Generic WAF',
            'X-CDN': {
                'Incapsula': 'Incapsula',
            },
            'X-Powered-By': {
                'ASP.NET': 'Microsoft ASP.NET',
                'Akamai': 'Akamai',
            },
            'X-Proxy-ID': 'Akamai',
            'X-Edge-IP': 'Akamai',
            'X-Edge-Location': 'Akamai',
            'X-Download-Options': 'Generic WAF',
            'X-XSS-Protection': 'Generic WAF',
            'X-Content-Type-Options': 'Generic WAF',
            'X-Akamai-Transformed': 'Akamai',
        }

        # Check for WAF signatures in the headers
        detected_wafs = []

        for header, signature in waf_signatures.items():
            if header in response.headers:
                if isinstance(signature, dict):
                    for sig_key, waf_name in signature.items():
                        if sig_key.lower() in response.headers[header].lower():
                            detected_wafs.append(waf_name)
                else:
                    detected_wafs.append(signature)

        # Prepare output content
        output_content = ""
        if detected_wafs:
            output_content += 'Detected WAF(s):\n'
            for waf in detected_wafs:
                output_content += f'- {waf}\n'
        else:
            output_content += 'No known WAF detected\n'

        # Print to console
        print("\n[+]"+output_content)

        active_recon_folder = os.path.join(target_folder, "Active Recon")

        # Create folders if they don't exist
        os.makedirs(active_recon_folder, exist_ok=True)

        # Write WAF detection result to a file
        waf_detection_file_path = os.path.join(active_recon_folder, f"{url}_waf_detection.txt")
        with open(waf_detection_file_path, 'w') as file:
            file.write(output_content)
            
        print(f"\n[+] WAF detection results saved to {waf_detection_file_path}")

    except requests.RequestException as e:
        error_message = f"\n[!] Error detecting WAF: {e}\n"
        print(error_message)



# Port Scanning Module

def scan_port(host, port):

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            result = s.connect_ex((host, port))
            if result == 0:
                return f"Port {port} is open"
            else:
                return f"Port {port} is closed"
    except Exception as e:
        return f"Port {port} - Error: {str(e)}"



def port_scan(host):
    
    # Define folder structure
    target_folder = host
    
    print("\n[#] Please Wait...\n")
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in range(0, 1024)}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and 'open' in result.lower():
                open_ports.append(result)

    # Print all open ports at the end in green
    print(f"\n[+] Open ports for {host}:\n")
    for port_info in open_ports:
        print(Fore.GREEN + port_info)
    
    
    active_recon_folder = os.path.join(target_folder, "Active Recon")

    # Create folders if they don't exist
    os.makedirs(active_recon_folder, exist_ok=True)

    # Write open ports to a file
    open_ports_file_path = os.path.join(active_recon_folder, f"{host}_open_ports.txt")
    with open(open_ports_file_path, 'w') as file:
        for port_info in open_ports:
            file.write(port_info + "\n")
    
    print(f"\n[+] Port scanning results saved to {open_ports_file_path}\n")



# Active Recon Modules

def active_recon_module():
    global global_target
    target = global_target or input("\n[+] Enter IP address or domain for reconnaissance: ").strip()

    try:
        ip_address = get_ip_address(target)
        if ip_address:
            print(f"\n[+] Target IP Address: {ip_address}\n")
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')

                banner()
                display_active_recon_options()
                choice = input("\n[+] Enter your passive recon choice (1-7): ").strip()

                if choice == '1':
                    website_header_analysis(target if ip_address else f"http://{target}")
                
                elif choice == '2':
                    identify_technology_stack(target if ip_address else f"http://{target}")
                
                elif choice == '3':
                    website_link_enumeration(target if ip_address else f"http://{target}")

                elif choice == '4':
                    gather_subdomains(target if ip_address else f"http://{target}")

                elif choice == '5':
                    detect_waf(target if ip_address else f"http://{target}")
                
                elif choice == '6':
                    port_scan(target if ip_address else f"http://{target}")
                    
                elif choice == '7':
                    break

                else:
                    print("\n[-] Invalid choice. Please enter a number between 1 and 6.\n")
                
                cont = input("\n[?] Do you want to perform another passive recon action? (yes/no): ").strip().lower()
                if cont != 'yes':
                    break
        else:
            print("\n[!] Unable to resolve IP address or domain.\n")

    except Exception as e:
        print(f"\n[!] Error: {e}")



######################################################################################################################
######################################################################################################################

# ███████ ███████  ██████ ██    ██ ██████  ██ ████████ ██    ██      █████  ██    ██ ██████  ██ ████████ 
# ██      ██      ██      ██    ██ ██   ██ ██    ██     ██  ██      ██   ██ ██    ██ ██   ██ ██    ██    
# ███████ █████   ██      ██    ██ ██████  ██    ██      ████       ███████ ██    ██ ██   ██ ██    ██    
#      ██ ██      ██      ██    ██ ██   ██ ██    ██       ██        ██   ██ ██    ██ ██   ██ ██    ██    
# ███████ ███████  ██████  ██████  ██   ██ ██    ██       ██        ██   ██  ██████  ██████  ██    ██    
                                                                                                    

######################################################################################################################
######################################################################################################################



# Security Audit option menu

def display_security_audit_options():
    recon_types = {
        1: 'Audit IP Address/Domain',
        2: 'Audit DNS',
        7: 'Back',
        # Add more recon types as needed
    }
    
    print("\n[+] Security Auditing Options:\n")
    for option, audit_type in recon_types.items():
        print(f"[{option}] {audit_type}")



# Read Saved Fils For Auditing
# Function to read data from a file and return it as a string
def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "File not found."
    
    

# IP/Domain Auditing
# Function to analyze security risks based on WHOIS and IP/ASN data

def analyze_and_write_security_audit_report(domain):
    # Read WHOIS data
    whois_file_path = f'{domain}/Passive Recon/{domain}_whois.txt'
    whois_data = read_file(whois_file_path)

    # Read IP range and ASN data
    ip_asn_file_path = f'{domain}/Passive Recon/{domain}_asn_info.txt'
    ip_asn_data = read_file(ip_asn_file_path)

    # Analyze security risks based on the data
    def analyze_security_risks(whois_data, ip_asn_data):
        risks = []
        
        # Example checks (you can add more detailed checks based on your needs)
        if "privacy" in whois_data.lower():
            risks.append(("\n[!] WHOIS data contains privacy-protected information, which might be used for masking malicious activities.", "\033[93m"))  # Yellow
        
        if "cloudflare" in whois_data.lower():
            risks.append(("\n[-] The domain uses Cloudflare services, which might indicate protection against DDoS attacks but could also mask the true origin of the server.", "\033[92m"))  # Green
        
        if "asn" in ip_asn_data.lower():
            risks.append(("\n[!] ASN details found. Ensure the ASNs are from reputable sources.", "\033[93m"))  # Yellow
        
        return risks

    # Get security risks
    security_risks = analyze_security_risks(whois_data, ip_asn_data)

    # Format security risks for writing to file
    security_risks_content = "\n".join([f"{color}{risk}\033[0m" for risk, color in security_risks])

    # Write security audit report to file
    audit_report_file_path = f'{domain}/Security Auditing/{domain}_ip_domain_audit.txt'
    os.makedirs(os.path.dirname(audit_report_file_path), exist_ok=True)
    with open(audit_report_file_path, 'w') as report_file:
        report_file.write("Security Audit Report\n\n")
        report_file.write(f"Domain: {domain}\n\n")
        report_file.write("WHOIS Information:\n")
        report_file.write(whois_data + "\n\n")
        report_file.write("IP/ASN Information:\n")
        report_file.write(ip_asn_data + "\n\n")
        report_file.write("Security Risks:\n")
        report_file.write(security_risks_content + "\n")


    # Print security risks to console with color codings
    print("\n\n[+] Security Risks:\n")
    for risk, color in security_risks:
        print(f"{color}{risk}\033[0m")

    print(f"\n[+] Security audit file saved at: {audit_report_file_path}\n\n")




# DNS Auditing

# Function to perform DNS zone transfer and analyze the results
def dns_audit(domain):
        
        
        # Read DNS data
        dns_file_path = f'{domain}/Passive Recon/{domain}_dns_info.txt'
        
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # Regex pattern for matching IPv4 addresses
        ip_addresses = re.findall(ip_pattern, read_file(dns_file_path))
        
        # Initialize risks list
        risks = []
        
        # Perform DNS zone transfer for each IP address
        print("\n\n[#] Please Wait...\n")
        
        for ip in ip_addresses:
            try:
                
                # Perform DNS zone transfer using dig command
                command = f"dig axfr @{ip} {domain}"
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()

                # Check if there was any output from dig
                if stdout:
                    risks.append((f"DNS Zone Transfer failed for IP: {ip}\n{stdout.decode('utf-8')}", "\033[92m"))  # Green
                else:
                    risks.append((f"DNS Zone Transfer successful for IP: {ip}\n{stdout.decode('utf-8')}", "\033[91m"))  # Red

            except Exception as e:
                risks.append((f"Error performing DNS zone transfer for IP {ip}: {str(e)}", "\033[91m"))  # Red

        # Format risks for saving to file
        risks_content = "\n\n".join([f"{color}{risk}\033[0m" for risk, color in risks])

        # Write results to file
        audit_report_file_path = f'{domain}/Security Auditing/{domain}_dns_audit_zone_transfer_report.txt'
        os.makedirs(os.path.dirname(audit_report_file_path), exist_ok=True)
        with open(audit_report_file_path, 'w') as report_file:
            report_file.write("DNS Zone Transfer Audit Report\n\n")
            report_file.write(f"Domain: {domain}\n\n")
            report_file.write("Security Risks:\n")
            report_file.write(risks_content + "\n")


        # Print risks to console with color codings
        print("\n[+] DNS Zone Transfer Audit Risks:\n")
        for risk, color in risks:
            print(f"{color}{risk}\033[0m")
            

        print(f"\n[+] DNS zone transfer audit report generated at: {audit_report_file_path}\n\n")






# Security Audit Modules

def security_audit_module():
    global global_target
    target = global_target or input("\n[+] Enter IP address or domain for reconnaissance: ").strip()

    try:
        ip_address = get_ip_address(target)
        if ip_address:
            print(f"\n[+] Target IP Address: {ip_address}\n")
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')

                banner()
                display_security_audit_options()
                choice = input("\n[+] Enter your security audit choice (1-3): ").strip()

                if choice == '1':
                    analyze_and_write_security_audit_report(target if ip_address else f"http://{target}")
                    
                if choice == '2':
                    dns_audit(target if ip_address else f"http://{target}")

                elif choice == '3':
                    break

                else:
                    print("\n[-] Invalid choice. Please enter a number between 1 and 3.\n")
                
                cont = input("\n[?] Do you want to perform another security audit? (yes/no): ").strip().lower()
                if cont != 'yes':
                    break
        else:
            print("\n[!] Unable to resolve IP address or domain.\n")

    except Exception as e:
        print(f"\n[!] Error: {e}")



######################################################################################################################
######################################################################################################################

# ██████  ███████ ██████   ██████  ██████  ████████ ██ ███    ██  ██████  
# ██   ██ ██      ██   ██ ██    ██ ██   ██    ██    ██ ████   ██ ██       
# ██████  █████   ██████  ██    ██ ██████     ██    ██ ██ ██  ██ ██   ███ 
# ██   ██ ██      ██      ██    ██ ██   ██    ██    ██ ██  ██ ██ ██    ██ 
# ██   ██ ███████ ██       ██████  ██   ██    ██    ██ ██   ████  ██████  


######################################################################################################################
######################################################################################################################


# Folder Structure

def create_folder_structure(target):
    # Ensure main folder for target exists
    if not os.path.exists(target):
        os.makedirs(target)
    
    # Create subfolders for each type of reconnaissance
    recon_types = ['Passive Recon', 'Active Recon', 'Security Auditing']
    for recon_type in recon_types:
        recon_folder = os.path.join(target, recon_type)
        if not os.path.exists(recon_folder):
            os.makedirs(recon_folder)

    print(f"\n[+] Folder structure created for {target}\n")
    

# Generate Report option menu

def display_report_banner():
    report_types = {
        1: 'HTML Format',
        2: 'PDF Format (Convert HTML to PDF)',
        3: 'Back',
        # Add more recon types as needed
    }
    
    print("\n[*] Report Options:\n")
    for option, report_type in report_types.items():
        print(f"[{option}] {report_type}")


# Generate HTML Report
def generate_html_report(company, passive_recon_data, active_recon_data, security_audit_data):
    
    # Current timestamp
    # timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Example HTML template
    html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Audit Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    width: 80%;
                    margin: auto;
                    padding: 20px;
                    background-color: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    text-align: center;
                    color: #0056b3;
                }}
                .section {{
                    margin-bottom: 20px;
                }}
                h2 {{
                    background-color: #0056b3;
                    color: white;
                    padding: 10px;
                    cursor: pointer;
                    margin: 0;
                }}
                .content {{
                    padding: 10px;
                    border: 1px solid #ccc;
                    display: block;
                    background-color: #fafafa;
                }}
                .timestamp {{
                    text-align: right;
                    font-size: 12px;
                    color: #666;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Audit Report</h1>
                <h1 style="color:Orange;  border-bottom: 2px solid #0056b3;
                    padding-bottom: 10px;">{company}</h1>
                <br>

                <div class="section">
                    <h2 onclick="toggleContent('passive_recon')">[+] Passive Recon</h2>
                    <div id="passive_recon" class="content">
                        {passive_recon_data}
                    </div>
                </div>

                <div class="section">
                    <h2 onclick="toggleContent('active_recon')">[+] Active Recon</h2>
                    <div id="active_recon" class="content">
                        {active_recon_data}
                    </div>
                </div>

                <div class="section">
                    <h2 onclick="toggleContent('security_audit')">[+] Security Auditing</h2>
                    <div id="security_audit" class="content">
                        {security_audit_data}
                    </div>
                </div>

                <div class="timestamp">
                    Generated on {timestamp}
                </div>
            </div>

            <script>
                function toggleContent(sectionId) {{
                    var content = document.getElementById(sectionId);
                    if (content.style.display === "none" || content.style.display === "") {{
                        content.style.display = "block";
                    }} else {{
                        content.style.display = "none";
                    }}
                }}
                
                toggleContent('passive_recon');
                toggleContent('active_recon');
                toggleContent('security_audit');
                
            </script>
        </body>
        </html>
        """


    # Format the HTML template with data
    html_content = html_template.format(
        company=company,
        passive_recon_data=passive_recon_data,
        active_recon_data=active_recon_data,
        security_audit_data=security_audit_data,
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    # Write the HTML content to a file
    with open("security_audit_report.html", "w") as file:
        file.write(html_content)

    print("\n\n[+] HTML report generated successfully.\n\n")
    



# Reading Saved Files

def generate_dynamic_template(domain):

    def read_file_content(file_path):
        with open(file_path, 'r') as file:
            return file.read()
        
    company = f"{domain}"
        
        
    # Reading Whois txt file
        
    # Assuming you have the WHOIS lookup text file path
    whois_file_path = f"{domain}/Passive Recon/{domain}_whois.txt"

    # Initialize an empty string to hold the formatted WHOIS content
    formatted_whois_content = ""

    # Read the WHOIS lookup results from the text file line by line
    try:
        with open(whois_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_whois_content += line.strip() + "<br>\n"

    except FileNotFoundError:
        formatted_whois_content = "No WHOIS lookup results available."


    # Reading Request Headers file
        
    # Assuming you have the request headers text file path
    request_header_file_path = f"{domain}/Passive Recon/{domain}_request_headers.txt"

    # Initialize an empty string to hold the formatted content
    formatted_request_header_content = ""

    # Read the results from the text file line by line
    try:
        with open(request_header_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_request_header_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_request_header_content = "No Request Header results available."
    
    
    # Reading Response Headers file
        
    # Assuming you have the response headers text file path
    response_header_file_path = f"{domain}/Passive Recon/{domain}_response_headers.txt"

    # Initialize an empty string to hold the formatted content
    formatted_response_header_content = ""

    # Read the results from the text file line by line
    try:
        with open(response_header_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_response_header_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_response_header_content = "No Response Header results available."


    # Reading Missing Headers file
        
    missing_header_file_path = f"{domain}/Passive Recon/{domain}_security_evaluation.txt"

    # Initialize an empty string to hold the formatted content
    formatted_missing_header_content = ""

    # Read the results from the text file line by line
    try:
        with open(missing_header_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_missing_header_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_missing_header_content = "No Missing Header results available."


    # Reading Taget ASN and IP Range Lookup file
        
    asn_ip_file_path = f"{domain}/Passive Recon/{domain}_asn_info.txt"

    # Initialize an empty string to hold the formatted content
    formatted_asn_ip_content = ""

    # Read the results from the text file line by line
    try:
        with open(asn_ip_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_asn_ip_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_asn_ip_content = "No ASN and IP Range results available."
         

    # Reading Taget DNS Lookup file
        
    dns_file_path = f"{domain}/Passive Recon/{domain}_dns_info.txt"

    # Initialize an empty string to hold the formatted content
    formatted_dns_content = ""

    # Read the results from the text file line by line
    try:
        with open(dns_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_dns_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_dns_content = "No DNS results available."


    # Reading Target Mail Server Lookup file
        
    mx_file_path = f"{domain}/Passive Recon/{domain}_mx_info.txt"

    # Initialize an empty string to hold the formatted content
    formatted_mx_content = ""

    # Read the results from the text file line by line
    try:
        with open(mx_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_mx_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_mx_content = "No Mail Server results available."


    # Reading Target Name Server Lookup file
        
    ns_file_path = f"{domain}/Passive Recon/{domain}_ns_info.txt"

    # Initialize an empty string to hold the formatted content
    formatted_ns_content = ""

    # Read the results from the text file line by line
    try:
        with open(ns_file_path, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_ns_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_ns_content = "No Name Server results available."
         
         
   
    # Reading Target Email Lookup file
    email_file_path = f"{domain}/Passive Recon/{domain}_emails.csv"

    # Initialize an empty string to hold the formatted content
    formatted_email_content = ""

    # Read the results from the CSV file line by line
    try:
        with open(email_file_path, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                # Join the row elements with a comma and add HTML line break
                formatted_email_content += ', '.join(row).strip() + "<br>\n"

    except FileNotFoundError:
        formatted_email_content = "No Email results available."


    # Sending the passive recon data to generate_html_report() function

    passive_recon_data = f"""

        <h3>[1] Whois Lookup Results</h3>
        <p>{formatted_whois_content}</p>
        <br>
        <h3>[2] Website Headers Found</h3>
        <ul>
            <li>
                <h4>
                    Request Headers
                </h4>
                <p>
                    {formatted_request_header_content}
                </p>
            </li>
                <li>
                <h4>
                    Response Headers
                </h4>
                <p>
                    {formatted_response_header_content}
                </p>
            </li>
                <li>
                <h4>
                    Missing Headers
                </h4>
                <p>
                    {formatted_missing_header_content}
                </p>
            </li>
        </ul>
        <br>
        <h3>[3] ASN and IP Ranges Found</h3>
        <p>{formatted_asn_ip_content}</p>
        <br>
        <h3>[4] DNS Lookup Results</h3>
        <p>{formatted_dns_content}</p>
        <br>
        <h3>[5] Mail Servers Found</h3>
        <p>{formatted_mx_content}</p>
        <br>
        <h3>[6] Name Servers Found</h3>
        <p>{formatted_ns_content}</p>
        <br>
        <h3>[7] Emails Found</h3>
        <p>{formatted_email_content}</p>
        <br>
    """


    # Reading Request Headers file
        
    # Assuming you have the request headers text file path
    request_header_file = f"{domain}/Active Recon/{domain}_request_headers.txt"

    # Initialize an empty string to hold the formatted content
    formatted_request_header = ""

    # Read the results from the text file line by line
    try:
        with open(request_header_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_request_header += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_request_header = "No Request Header results available."
    
    
    # Reading Response Headers file
        
    # Assuming you have the response headers text file path
    response_header_file = f"{domain}/Active Recon/{domain}_response_headers.txt"

    # Initialize an empty string to hold the formatted content
    formatted_response_header = ""

    # Read the results from the text file line by line
    try:
        with open(response_header_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_response_header += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_response_header = "No Response Header results available."


    # Reading Missing Headers file
        
    missing_header_file = f"{domain}/Active Recon/{domain}_security_evaluation.txt"

    # Initialize an empty string to hold the formatted content
    formatted_missing_header = ""

    # Read the results from the text file line by line
    try:
        with open(missing_header_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_missing_header += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_missing_header = "No Missing Header results available."


    # Reading Tech Stack Enum file
        
    tech_enum_file = f"{domain}/Active Recon/{domain}_technology_stack.txt"

    # Initialize an empty string to hold the formatted content
    tech_enum_content = ""

    # Read the results from the text file line by line
    try:
        with open(tech_enum_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                tech_enum_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         tech_enum_content = "No Technology Enumeration results available."
         
    
    
    # Reading Web Links Enum file
        
    web_link_file = f"{domain}/Active Recon/{domain}_active_links.txt"

    # Initialize an empty string to hold the formatted content
    web_link_content = ""

    # Read the results from the text file line by line
    try:
        with open(web_link_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                web_link_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         web_link_content = "No Active Web Link results available."



    # Reading Meta Tags Enum file
        
    meta_tags_file = f"{domain}/Active Recon/{domain}_meta_tags.txt"

    # Initialize an empty string to hold the formatted content
    meta_tags_content = ""

    # Read the results from the text file line by line
    try:
        with open(meta_tags_file, 'r') as file:
            for line in file:
                # Escape HTML characters
                escaped_line = html.escape(line.strip())
                # Add HTML line break
                meta_tags_content += escaped_line + "<br>\n"
    except FileNotFoundError:
        meta_tags_content = "No Meta Tags results available."
         
         

    # Reading Response Headers2 file
        
    # Assuming you have the response headers text file path
    response_header_file2 = f"{domain}/Active Recon/{domain}_response_headers2.txt"

    # Initialize an empty string to hold the formatted content
    formatted_response_header2 = ""

    # Read the results from the text file line by line
    try:
        with open(response_header_file2, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                formatted_response_header2 += line.strip() + "<br>\n"

    except FileNotFoundError:
         formatted_response_header2 = "No Response Header results available."



    # Reading Sudomain Enum file
        
    subdomain_enum_file = f"{domain}/Active Recon/{domain}_subdomains.txt"

    # Initialize an empty string to hold the formatted content
    subdomain_enum_content = ""

    # Read the results from the text file line by line
    try:
        with open(subdomain_enum_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                subdomain_enum_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         subdomain_enum_content = "No Subdomain Enumeration results available."
         
         
    # Reading WAF Enum file
        
    waf_enum_file = f"{domain}/Active Recon/{domain}_waf_detection.txt"

    # Initialize an empty string to hold the formatted content
    waf_enum_content = ""

    # Read the results from the text file line by line
    try:
        with open(waf_enum_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                waf_enum_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         waf_enum_content = "No WAF results available."
         
         

    # Reading ports Enum file
        
    port_enum_file = f"{domain}/Active Recon/{domain}_open_ports.txt"

    # Initialize an empty string to hold the formatted content
    port_enum_content = ""

    # Read the results from the text file line by line
    try:
        with open(port_enum_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                port_enum_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         port_enum_content = "No Open Ports results available."



    # Sending the passive recon data to generate_html_report() function
    
    active_recon_data = f"""
    
        <h3>[1] Website Headers Found</h3>
            <ul>
                <li>
                    <h4>
                        Request Headers
                    </h4>
                    <p>
                        {formatted_request_header}
                    </p>
                </li>
                    <li>
                    <h4>
                        Response Headers
                    </h4>
                    <p>
                        {formatted_response_header}
                    </p>
                </li>
                    <li>
                    <h4>
                        Missing Headers
                    </h4>
                    <p>
                        {formatted_missing_header}
                    </p>
                </li>
            </ul>
        <br>
        <h3>[2] Web Links/Meta Tags/Response Headers Found</h3>
            <ul>
                <li>
                    <h4>
                        Web Links
                    </h4>
                    <p>
                        {web_link_content}
                    </p>
                </li>
                    <li>
                    <h4>
                        Meta Tags
                    </h4>
                    <p>
                        {meta_tags_content}
                    </p>
                </li>
                    <li>
                    <h4>
                        Response Headers
                    </h4>
                    <p>
                        {formatted_response_header2}
                    </p>
                </li>
            </ul>
        <br>
        <h3>[3] Subdomains Found</h3>
        <p>{subdomain_enum_content}</p>
        <br>
        <h3>[4] WAF Detected</h3>
        <p>{waf_enum_content}</p>
        <br>
        <h3>[5] Open Ports Found</h3>
        <p>{port_enum_content}</p>
        <br>
    
    """
    
    
    
    # Security Audit Data Section
    
    # Reading IP and Domain Audit file
        
    ip_domain_audit_file = f"{domain}/Security Auditing/{domain}_ip_domain_audit.txt"

    # Initialize an empty string to hold the formatted content
    ip_domain_audit_content = ""

    # Read the results from the text file line by line
    try:
        with open(ip_domain_audit_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                ip_domain_audit_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         ip_domain_audit_content = "No audit results available."
    
    
    
    # Reading DNS Audit file
        
    dns_audit_file = f"{domain}/Security Auditing/{domain}_dns_audit_zone_transfer_report.txt"

    # Initialize an empty string to hold the formatted content
    dns_audit_content = ""

    # Read the results from the text file line by line
    try:
        with open(dns_audit_file, 'r') as file:
            for line in file:
                # Strip any leading or trailing whitespace and add HTML line break
                dns_audit_content += line.strip() + "<br>\n"

    except FileNotFoundError:
         dns_audit_content = "No audit results available."
    
    
    
    
    # Sending the Auditing data to generate_html_report() function
         
    security_audit_data = f"""
    
        <h3>[1] IP/Domain Audit Result</h3>
        <p>{ip_domain_audit_content}</p>
        <br>
        <h3>[2] DNS Audit (DNS Zone Transfer Test)</h3>
        <p>{dns_audit_content}</p>
        <br>
    
    """




    # Calling generate_html_report() function
    generate_html_report(company, passive_recon_data, active_recon_data, security_audit_data)







# PDF Report Generation

def html_to_pdf(domain):
    
    html_file = 'security_audit_report.html'
    output_pdf = f'{domain}_security_audit_report.pdf'
    
    try:
        HTML(html_file).write_pdf(output_pdf)
        print(f'\n[+] PDF successfully generated: {output_pdf}\n')
    except Exception as e:
        print(f'\n[-] Error generating PDF: {str(e)}\n')


# Reporting Module
def reporting_module():
    
    global global_target
    target = global_target or input("\n\n[+] Enter IP address or domain for reconnaissance: ").strip()

    try:
        ip_address = get_ip_address(global_target)
        if ip_address:
            print(f"\n[+] Target IP Address: {ip_address}\n")
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')

                banner()
                display_report_banner()
                choice = input("\n\n[+] Enter your report format choice (1-3): ").strip()

                if choice == '1':
                    generate_dynamic_template(target)
                    input()
                
                elif choice == '2':
                    html_to_pdf(target)
                    input()
                
                elif choice == '3':
                    break

                else:
                    print("\n[-] Invalid choice. Please enter a number between 1 and 3.\n")
                
                cont = input("\n[*] Do you want to generate another report? (yes/no): ").strip().lower()
                if cont != 'yes':
                    break
        else:
            print("\n[!] Unable to resolve IP address or domain.\n")

    except Exception as e:
        print(f"[!] Error: {e}")
    



######################################################################################################################
######################################################################################################################

# ███    ███  █████  ██ ███    ██     ███████ ██    ██ ███    ██  ██████ ████████ ██  ██████  ███    ██ 
# ████  ████ ██   ██ ██ ████   ██     ██      ██    ██ ████   ██ ██         ██    ██ ██    ██ ████   ██ 
# ██ ████ ██ ███████ ██ ██ ██  ██     █████   ██    ██ ██ ██  ██ ██         ██    ██ ██    ██ ██ ██  ██ 
# ██  ██  ██ ██   ██ ██ ██  ██ ██     ██      ██    ██ ██  ██ ██ ██         ██    ██ ██    ██ ██  ██ ██ 
# ██      ██ ██   ██ ██ ██   ████     ██       ██████  ██   ████  ██████    ██    ██  ██████  ██   ████ 

######################################################################################################################
######################################################################################################################


# Main function to display the menu and call the appropriate functions

def main():

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        banner()
        print("\n[*] Choose an option:\n")
        print("[1] Set Target IP/Domain (example.com)")
        print("[2] Passive Recon")
        print("[3] Active Recon")
        print("[4] Security Audit")
        print("[5] Reporting")
        print("[6] Exit")

        choice = input("\n\n[+] Enter your choice (1-6): ").strip()

        if choice == '1':
            set_global_target()
        
        elif choice == '2':
            passive_recon_module()
        
        elif choice == '3':
            active_recon_module()
        
        elif choice == '4':
            security_audit_module()
        
        elif choice == '5':
            reporting_module()
        
        elif choice == '6':
            print("\n[*] Exiting the program...\n")
            break
        
        else:
            print("\n[-] Invalid choice. Please enter a number between 1 and 6.\n\n")


if __name__ == "__main__":
    main()
