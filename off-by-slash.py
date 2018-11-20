from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.net import URL

# https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

# Attempts to detect path traversal caused via a common NGINX misconfiguration.
# Example:
#       For the URL: https://example.com/folder1/folder2/static/main.css it generates the following links (only if the folders seem vulnerable):
#
#       https://example.com/folder1../folder1/folder2/static/main.css
#       https://example.com/folder1../%s/folder2/static/main.css
#       https://example.com/folder1/folder2../folder2/static/main.css
#       https://example.com/folder1/folder2../%s/static/main.css
#       https://example.com/folder1/folder2/static../static/main.css
#       https://example.com/folder1/folder2/static../%s/main.css
#
#       where %s are common directories used in alias paths based on top 10k nginx configuration files from GH (thanks @TomNomNom), see directories.txt.

class BurpExtender(IBurpExtender, IScannerCheck):
    scanned_urls = set()

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("NGINX Alias Traversal")

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._callbacks.registerScannerCheck(self)

        self.enableDirectoryGuessing = True
        with open("directories.txt", "r") as f:
            self.common_directories = [x.strip() for x in f.readlines()]
            
        self._stdout.println("GitHub: https://github.com/bayotop/off-by-slash/")
        self._stdout.println("Contact: https://twitter.com/_bayotop")
        self._stdout.println("")
        self._stdout.println("Successfully initialized!")

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        scan_issues = []

        if not self.isGet(baseRequestResponse.getRequest()):
            return None

        if not self.isStaticResource(baseRequestResponse):
            return None

        # Am I missing cases because of this?
        if not self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() == 200:
            return None

        # Prevent testing same paths repeadetly
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl().toString()
        url = url[:url.rindex("/")]

        if url in self.scanned_urls:
            return None
        
        self.scanned_urls.add(url)
        vulnerable, verifyingRequestResponse = self.detectAliasTraversal(baseRequestResponse)

        if vulnerable:
            scan_issues.append(self.generateIssue(baseRequestResponse, verifyingRequestResponse))
                    
        return scan_issues

    def doPassiveScan(self, baseRequestResponse):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return existingIssue.getIssueName() == newIssue.getIssueName()

    def isGet(self, request):
        requestInfo = self._helpers.analyzeRequest(request)
        return requestInfo.getMethod() == "GET"

    def isStaticResource(self, requestResponse):
        # This likely needs adjustment. 
        return "." in self._helpers.analyzeRequest(requestResponse).getUrl().getPath().split("/")[-1]

    def detectAliasTraversal(self, requestResponse):
        originalUrl = self._helpers.analyzeRequest(requestResponse).getUrl()
        urls = self.generateUrls(originalUrl, requestResponse)

        for url in urls:
            verifyingRequestResponse = self._callbacks.makeHttpRequest(requestResponse.getHttpService(), self._helpers.buildHttpRequest(url))
            if self.compareResponses(requestResponse.getResponse(), verifyingRequestResponse.getResponse()):
                self._stdout.println("Vulnerable: %s" % url)
                return True, verifyingRequestResponse

        return False, None 

    def generateUrls(self, url, requestResponse):
        urls = []
        path = url.getPath()
        parts = filter(None, path.split("/"))

        for part in parts:
            if "." in part:
                continue

            # Checks if /part../ results in 403
            if not self.quickCheck(url, part, requestResponse):
                continue

            self._stdout.println("Potentially vulnerable: %s" % url)
            
            replacement = "/%s../%s/" % (part, part)
            urls.append(URL(url.toString().replace("/%s/" % part, replacement)))
            if self.enableDirectoryGuessing:
                urls = urls + self.guessDirectories(url, part)

        return urls
    
    def quickCheck(self, url, part, requestResponse):
        replacement = "/%s../" % part
        url = url.toString().replace("/%s/" % part, replacement)
        url = URL(url[:url.index("../") + 3])

        check = self._callbacks.makeHttpRequest(requestResponse.getHttpService(), self._helpers.buildHttpRequest(url))
        return self._helpers.analyzeResponse(check.getResponse()).getStatusCode() == 403

    def guessDirectories(self, url, part):
        urls = []

        for directory in self.common_directories:
            replacement = "/%s../%s/" % (part, directory)
            urls.append(URL(url.toString().replace("/%s/" % part, replacement))) 

        return urls

    def compareResponses(self, oResponse, vResponse):
        vResponseInfo = self._helpers.analyzeResponse(vResponse)

        if vResponseInfo.getStatusCode() != 200:
            return False

        vBodyOffset = vResponseInfo.getBodyOffset()
        vBody = vResponse.tostring()[vBodyOffset:]

        oResponseInfo = self._helpers.analyzeResponse(oResponse)
        oBodyOffset = oResponseInfo.getBodyOffset()
        oBody = oResponse.tostring()[oBodyOffset:]

        return str(oBody) == str(vBody)

    def generateIssue(self, baseRequestResponse, verifyingRequestResponse):
        name = "Path traversal via misconfigured NGINX alias"
        severity = "High"
        confidence = "Firm"
        detail = '''
Found path traversal at:<br/>
<ul>
<li>Original url: %s</li>
<li>Verification url: %s</li>
</ul>        
''' % (self._helpers.analyzeRequest(baseRequestResponse).getUrl(), self._helpers.analyzeRequest(verifyingRequestResponse).getUrl())
# https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md
        background = '''
The alias directive is used to replace path of the specified location. For example, with the following configuration:<br/><br/>

<pre>location /i/ { 
        alias /data/w3/images/;
}</pre><br/>
on request of /i/top.gif, the file /data/w3/images/top.gif will be sent.<br/><br/>
        
But, if the location doesn't ends with directory separator (i.e. /):<br/><br/>

<pre>location /i {
        alias /data/w3/images/
}</pre><br/>
on request of /i../app/config.py, the file /data/w3/app/config.py will be sent.<br/><br/>

In other words, the incorrect configuration of alias could allow an attacker to read file stored outside the target folder.
'''
        remediation = "Find all 'alias' directives and make sure that the parent prefixed location ends with and directory separator."

        return ScanIssue(baseRequestResponse.getHttpService(),
                         self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                         [baseRequestResponse, verifyingRequestResponse],
                         name, detail, background, confidence, severity, remediation)

class ScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, background, confidence, severity, remediation):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Background = background
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        self.Remediation = remediation
        return

    def getUrl(self):
        return self.Url

    def getIssueName(self):
        return self.Name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.Severity

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return self.Background

    def getRemediationBackground(self):
        return self.Remediation

    def getIssueDetail(self):
        return self.Detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService