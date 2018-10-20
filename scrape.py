import sys
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 1. Use this to scrape a resource from a list of given URLs
# 2. In Burp start a new scan and them as "URLs to Scan"
# 3. Selectively disable other extensions adding active scanner checks and run a "Audit checks - extensions only" scan.

RESOURCES_PATTERN = r'(?:(?:href|src)=(?:["\']([^\'"]*)[\'"]|([^\s<>]+)))'

def scrape(urls):
    allurls = set()

    for url in urls:
        results = set()
        print("Scarping %s..." % url)
        try:
            content = requests.get(url, verify=False, timeout=3).content
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            print("Failed on %s: %s" % (url, sys.exc_info()[1]))
            continue

        matches = re.findall(RESOURCES_PATTERN, content.decode("utf-8"))

        for match in matches:
            for group in match:
                results.add(group)

        results = [result for result in results if is_same_origin(url, result) or is_relative(result)]
        results = [result for result in results if "." in result.split("/")[-1]]
        results = [get_full_url(url, result) for result in results]

        print("Found %s resources." % len(results))
        allurls = allurls.union(results)

    with open("results.txt", "w") as f:
        for url in allurls:
            f.write("%s\n" % url)

def is_same_origin(origin, url):
    return url.startswith(origin + "/") or url.startswith("//%s/" % origin.split("/")[2])

def is_relative(url):
    return url.startswith("/") and not (url.startswith("//") or url.startswith("/\\"))

def get_full_url(origin, url):
    if url.startswith(origin):
        return url
    if url.startswith("//"):
        return origin.split("/")[0] + url
    if url.startswith("/"):
        return origin + url

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <domain_list>" % sys.argv[0])
        sys.exit()

    with open(sys.argv[1]) as f:
        urls = [line.strip().rstrip("/") for line in f.readlines()]

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    scrape(urls)