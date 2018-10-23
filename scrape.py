import multiprocessing
import sys
import re
import requests
import urllib3
from urllib.parse import urlparse

# 1. Use this to scrape a resource from a list of given URLs
# 2. In Burp start a new scan and them as "URLs to Scan"
# 3. Selectively disable other extensions adding active scanner checks and run a "Audit checks - extensions only" scan.

RESOURCES_PATTERN = r'(?:(?:href|src)=(?:["\']([^\'"]*)[\'"]|([^\s<>]+)))' # @d0nutptr
EXT_BLACKLIST = [r'html?', r'as.x?', r'php\d?']

RESULTS_FILE = "results.txt"
PROCESSES_COUNT = 4
DONE_FLAG = "__done__"

def initiate(pool, results, urls):
    jobs = []
    for url in urls:
        job = pool.apply_async(scrape, (url, results))
        jobs.append(job)

    try:
        for job in jobs:
            job.get()
    except KeyboardInterrupt:
        print("Killed.")
        try:
            pool.terminate()
            pool.close()
        finally:
            sys.exit(0)

def scrape(url, queue):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    results = set()

    print("Scraping %s ..." % url)
    try:
        response = requests.get(url, verify=False, timeout=3)
        if response.history:
            url = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(response.url))
        content = response.content
    except:
        print("Failed on %s: %s" % (url, sys.exc_info()[1]))
        return

    matches = re.findall(RESOURCES_PATTERN, content.decode("utf-8", "replace"))

    for match in matches:
        for group in match:
            results.add(group)

    results = [result for result in results if is_same_origin(url, result) or is_relative(result)]
    results = [result for result in results if ("." in result.split("/")[-1] and not is_blacklisted(result.split("/")[-1].split(".")[-1]))]
    results = [get_full_url(url, result) for result in results]

    print("Found %s resources on %s" % (len(results), url))

    for result in results:
        queue.put(result.replace(" ", "%20"))

def writer(queue):
    results = set()
    while True:
        try:
            entry = queue.get()
            if entry == DONE_FLAG:
                return results

            results.add(entry)
        except:
            # KeyboardInterrupt
            break

def is_same_origin(origin, url):
    return url.startswith(origin + "/") or url.startswith("//%s/" % origin.split("/")[2])

def is_relative(url):
    return url.startswith("/") and not (url.startswith("//") or url.startswith("/\\"))

def is_blacklisted(extension):
    return any(re.match(ep, extension) for ep in EXT_BLACKLIST)

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

    results = multiprocessing.Manager().Queue()
    p = multiprocessing.Pool(4)

    wjob = p.apply_async(writer, (results,))
    initiate(p, results, urls)

    results.put(DONE_FLAG)
    resources = wjob.get()
    p.close()

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        for resource in resources:
            f.write("%s\n" % resource)