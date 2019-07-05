# Derive
Recursive Batch File Downloader for PHP Path Traversal

Usage:
```
usage: derive.py [-h] -t TARGET -f FILE [--cookies COOKIES] [--proxy PROXY]
                 [-v]

Recursive Batch File Downloader

arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Remote webserver and path traversal location (eg.
                        http://<IP/hostname>/test.php?a=)
  -f FILE, --file FILE  File to download (eg. index.php)
  --cookies COOKIES     HTTP Cookies
  --proxy PROXY         IP of web proxy to go through (http://127.0.0.1:8080)
  -v, --verbose         Print verbose output

example: python3 derive.py -t http://127.0.0.1/hostname>/index.php?a= -f index.php -v
```
