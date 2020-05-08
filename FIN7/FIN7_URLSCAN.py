import urllib
import json
import time
import argparse
import textwrap
from urllib import request

# build list of possible GRIFFON URI


def f7():
    path = ["images", "image", "content", "fetch",
            "cdn", "pictures", "img", "info", "new"]
    file = ["create_logo", "get_image", "create_image", "show_ico", "show_jpg", "show_png", "sync", "show", "hide",
            "add", "new", "renew", "delete"]
    param = ["?type=name", "?request=page"]
    urls = []

    for p in path:
        for f in file:
            for pa in param:
                urls.append("%s/%s%s" % (p, f, pa))
    return urls

# Run queries in URLSCAN.IO


def runURLIO(queries):
    for query in queries:
        time.sleep(5)
        url = "https://urlscan.io/api/v1/search/?q=\"%s\"&size=10000" % (query)
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as res:
            urlList = res.read()
            urlList = json.loads(urlList)
            for list in urlList["results"]:
                print("%s,%s,%s,%s\n" % (
                    list["task"]["time"], list["task"]["url"], list["page"]["ip"], list["page"]["domain"]))


def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
GRIFFON C2 URLIO Search 
----------------------------------------------------------------
This script will iterate through all the possible URL combinations used in the GRIFFON beacon
and search https://urlscan.io/ for any matches There are no arguments needed to run.

Examples:
\t python FIN7_URLSCAN.py
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    runURLIO(f7())


if __name__ == "__main__":
    main()
