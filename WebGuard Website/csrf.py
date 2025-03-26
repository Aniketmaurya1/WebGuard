import requests
from bs4 import BeautifulSoup
import math
from collections import Counter
from urllib.parse import urljoin, urlparse, parse_qs
import time
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

class CSRFScanner:
    def __init__(self):
        self.visited_urls = set()
        self.stop_scanning = False
        self.results = []

    def calculate_entropy(self, token):
        if not token:
            return 0
        counter = Counter(token)
        token_length = len(token)
        entropy = 0
        for count in counter.values():
            p_x = count / token_length
            entropy += -p_x * math.log2(p_x)
        return entropy

    def normalize_url(self, url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        params_to_remove = ['pic', 'utm_source', 'utm_medium', 'utm_campaign']
        for param in params_to_remove:
            if param in query_params:
                del query_params[param]

        normalized_query = '&'.join(f"{k}={v[0]}" for k, v in query_params.items())
        normalized_url = parsed_url._replace(query=normalized_query).geturl()
        
        return normalized_url

    def extract_internal_links(self, soup, base_url):
        links = set()
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if urlparse(base_url).netloc == urlparse(full_url).netloc:
                links.add(full_url)
        return links

    def process_form(self, form, index, url, entropy_threshold):
        inputs = form.find_all('input')
        csrf_token_found = False

        for input_tag in inputs:
            input_name = input_tag.get('name', '').lower()
            token_value = input_tag.get('value', '')
            if 'csrf' in input_name or 'token' in input_name:
                csrf_token_found = True
                token_entropy = self.calculate_entropy(token_value)
                print(f"Form {index + 1}: CSRF token found in input field '{input_name}'. Token entropy is {token_entropy:.2f}.", flush=True)
                if token_entropy >= entropy_threshold:
                    print(f"Form {index + 1}: Token has sufficient entropy. The form is likely secure.", flush=True)
                else:
                    print(f"Form {index + 1}: Token entropy is too low! The form may be vulnerable.", flush=True)
                    self.results.append((url, f"Form {index + 1}: Token entropy is too low! The form may be vulnerable."))
        
        if not csrf_token_found:
            print(f"Form {index + 1}: No CSRF token found! The form may be vulnerable.", flush=True)
            self.results.append((url, f"Form {index + 1}: No CSRF token found! The form may be vulnerable."))

    def csrf_scanner(self, url, entropy_threshold=3.5):
        normalized_url = self.normalize_url(url)
        
        if normalized_url in self.visited_urls or self.stop_scanning:
            return
        self.visited_urls.add(normalized_url)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                print(f"Failed to access {url}. Status Code: 404 Not Found", flush=True)
                return
            elif response.status_code != 200:
                print(f"Failed to access {url}. Status Code: {response.status_code}", flush=True)
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                print(f"No forms found on {url}", flush=True)
            else:
                print(f"Scanning {len(forms)} forms on {url} for CSRF vulnerabilities...", flush=True)

            for index, form in enumerate(forms):
                self.process_form(form, index, url, entropy_threshold)
                if self.stop_scanning:
                    return

            internal_links = self.extract_internal_links(soup, url)
            for link in internal_links:
                self.csrf_scanner(link, entropy_threshold)
                if self.stop_scanning:
                    return
                time.sleep(1)  # Rate limiting

        except requests.RequestException as e:
            print(f"Error accessing {url}: {str(e)}", flush=True)

    def print_final_report(self):
        print("\n--- CSRF Scan Report ---", flush=True)
        if not self.results:
            print("No CSRF vulnerabilities found.", flush=True)
        else:
            for url, message in self.results:
                print(f"{url} - {message}", flush=True)
            print("\nMitigations:", flush=True)
            print("1. Always use CSRF tokens in forms that perform state-changing actions.", flush=True)
            print("2. Ensure CSRF tokens have high entropy and are unique for each session.", flush=True)
            print("3. Consider implementing SameSite cookies for additional protection.", flush=True)

if __name__ == "__main__":
    scanner = CSRFScanner()    
    try:
        if len(sys.argv) != 2:
            print("Usage: python csrf.py <target_url>", flush=True)
            sys.exit(1)

        target_url = sys.argv[1]
        scanner.csrf_scanner(target_url)
        scanner.print_final_report()

    except KeyboardInterrupt:
        scanner.stop_scanning = True
        print("Scanning stopped by user.", flush=True)