import requests
import re
from bs4 import BeautifulSoup
from termcolor import colored

# Function to read URLs from urls.txt file
def read_urls(file_name='urls.txt'):
    with open(file_name, 'r') as f:
        urls = f.readlines()
    return [url.strip() for url in urls]

# Function to save vulnerable URLs to a file
def save_vulnerable_ip(vulnerable_url, file_name='vulnerable_ip.txt'):
    with open(file_name, 'a') as f:
        f.write(vulnerable_url + '\n')

# Function to check for directory listing vulnerability
def check_directory_listing(url):
    try:
        response = requests.get(url)
        if response.status_code == 200 and "Index of" in response.text:
            print(colored(f"[+] Directory Listing Vulnerability: {url}", 'green'))
            save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking directory listing for {url}: {e}")

# Function to check for exposed .git directory
def check_git_exposure(url):
    try:
        response = requests.get(url + '/.git/')
        if response.status_code == 200:
            print(colored(f"[+] .git directory exposed: {url}", 'green'))
            save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking .git exposure for {url}: {e}")

# Function to check for sensitive file exposure (.env, config files)
def check_sensitive_files(url):
    sensitive_files = ['.env', 'wp-config.php', 'app/config', 'db.ini']
    try:
        for file in sensitive_files:
            response = requests.get(url + '/' + file)
            if response.status_code == 200:
                print(colored(f"[+] Sensitive file exposed ({file}): {url}", 'green'))
                save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking sensitive files for {url}: {e}")

# Function to check for API key exposure
def check_api_key_exposure(url):
    try:
        response = requests.get(url)
        if re.search(r'(AIza[0-9A-Za-z-_]{35}|sk_live_[0-9a-zA-Z]{24})', response.text):
            print(colored(f"[+] API Key Exposed: {url}", 'green'))
            save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking API key exposure for {url}: {e}")

# Function to check for exposed tokens in URL
def check_token_in_url(url):
    try:
        response = requests.get(url)
        if re.search(r'[\?&](token|auth|session)=[^&]+', url):
            print(colored(f"[+] Token exposed in URL: {url}", 'green'))
            save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking token exposure for {url}: {e}")

# Function to check for server headers and misconfigurations
def check_server_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        if 'Server' in headers:
            print(colored(f"[+] Server header exposed ({headers['Server']}): {url}", 'green'))
            save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking server headers for {url}: {e}")

# Function to check for unencrypted HTTP
def check_http_insecure(url):
    if url.startswith('http://'):
        print(colored(f"[+] Insecure HTTP detected: {url}", 'green'))
        save_vulnerable_ip(url)

# Function to check for misconfigured backup files
def check_backup_files(url):
    backup_files = ['backup.zip', 'backup.tar.gz', 'db_backup.sql']
    try:
        for file in backup_files:
            response = requests.get(url + '/' + file)
            if response.status_code == 200:
                print(colored(f"[+] Backup file exposed ({file}): {url}", 'green'))
                save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking backup files for {url}: {e}")

# Function to check for subdomain takeover
def check_subdomain_takeover(url):
    try:
        response = requests.get(url)
        if 'There isn't a GitHub Pages site here' in response.text or 'NoSuchBucket' in response.text:
            print(colored(f"[+] Possible subdomain takeover: {url}", 'green'))
            save_vulnerable_ip(url)
    except Exception as e:
        print(f"Error checking subdomain takeover for {url}: {e}")

# Function to perform all checks on each target
def check_vulnerabilities(url):
    check_directory_listing(url)
    check_git_exposure(url)
    check_sensitive_files(url)
    check_api_key_exposure(url)
    check_token_in_url(url)
    check_server_headers(url)
    check_http_insecure(url)
    check_backup_files(url)
    check_subdomain_takeover(url)

# Main function to process all targets from urls.txt
def main():
    urls = read_urls()
    for url in urls:
        print(f"Checking: {url}")
        check_vulnerabilities(url)

if __name__ == "__main__":
    main()
