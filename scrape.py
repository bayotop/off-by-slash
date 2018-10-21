import multiprocessing
import sys
import re
import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# 1. Use this to scrape a resource from a list of given URLs
# 2. In Burp start a new scan and them as "URLs to Scan"
# 3. Selectively disable other extensions adding active scanner checks and run a "Audit checks - extensions only" scan.

RESOURCES_PATTERN = r'(?:(?:href|src)=(?:["\']([^\'"]*)[\'"]|([^\s<>]+)))' # @d0nutptr

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
        pool.terminate()
        pool.close()
        sys.exit(0)

def scrape(url, queue):
    disable_warnings(InsecureRequestWarning)
    results = set()

    print("Scarping %s..." % url)
    try:
        content = requests.get(url, verify=False, timeout=3).content
    except:
        print("Failed on %s: %s" % (url, sys.exc_info()[1]))
        return

    matches = re.findall(RESOURCES_PATTERN, content.decode("utf-8"))

    for match in matches:
        for group in match:
            results.add(group)

    results = [result for result in results if is_same_origin(url, result) or is_relative(result)]
    results = [result for result in results if "." in result.split("/")[-1]]
    results = [get_full_url(url, result) for result in results]

    print("Found %s resources on %s." % (len(results), url))

    for result in results:
        queue.put(result)

def writer(queue):
    f = open(RESULTS_FILE, 'w') 
    while True:
        try:
            entry = queue.get()
        except:
            # KeyboardInterrupt
            break
        if entry == DONE_FLAG:
            break
        f.write(str(entry) + '\n')
        f.flush()
    f.close()

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

    results = multiprocessing.Manager().Queue()   
    p = multiprocessing.Pool(4)
    
    p.apply_async(writer, (results,))
    initiate(p, results, urls)

    results.put(DONE_FLAG)
    p.close()