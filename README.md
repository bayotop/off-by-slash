# off-by-slash
Burp extension to detect alias traversal via NGINX misconfiguration at scale. Requires Burp Professional.

![Issue](issue.png?raw=true "off-by-slash in Burp 2.0")

## Usage

1. git clone https://github.com/bayotop/off-by-slash/
2. Burp -> Extender -> Add -> find and select `off-by-slash.py`

The extension implements an active scanner check. Simply run a new scan, preferably with an "Audit checks - extensions only" configuration, on static resources identified via Burp's crawler. Alternatively, use `scrape.py` with a list of URLs to scrape static resources from. The results can be directly passed to a new Burp scan (Burp 2.0).

## Description

*https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf*

A server is assumed to be vulnerable if a request to an existing path like `https://example.com/static../` returns 403. To eliminate false positives the misconfiguration has to be confirmed by successfully requesting an existing resource via path traversal. This is done as follows:

For the URL https://example.com/folder1/folder2/static/main.css it generates the following links:

```
https://example.com/folder1../folder1/folder2/static/main.css
https://example.com/folder1../%s/folder2/static/main.css
https://example.com/folder1/folder2../folder2/static/main.css
https://example.com/folder1/folder2../%s/static/main.css
https://example.com/folder1/folder2/static../static/main.css
https://example.com/folder1/folder2/static../%s/main.css
```

Where `%s` are common directories used in alias paths based on around 9500 nginx configuration files from GH (thanks [@TomNomNom](https://twitter.com/TomNomNom)), see directories.txt.
