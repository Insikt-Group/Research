import shodan
import re
import argparse
import textwrap


def kopiluwak_match(ua):
    found = False
    # get only the last 32 characters of the UA
    ua_stripped = ua[-32:]
    # see if the last 32 characters of the array match the Kopiluwak regex
    matchObj = re.search("([0-9]{16}[a-zA-Z0-9]{16})", ua_stripped)
    if matchObj:
        found = True
    return found


def uaShodanCheck(ua, SHODAN_API_KEY):
    api = shodan.Shodan(SHODAN_API_KEY)
    scannedUA = {}
    try:
        # Search Shodan
        results = api.search(ua)

        # Show the results
        total = results["total"]

        # Iterate though the first 100, extracting the User-Agent and then checking to see if it matches the kopiluqak string
        for result in results["matches"]:
            headers = result["data"].splitlines()
            for header in headers:
                if "User-Agent" in header:
                    ua = header.split(":", 1)
                    found = kopiluwak_match(ua[1])
                    scannedUA[ua[1]] = [result["ip_str"], found]

    except shodan.APIError as e:
        print("Error: {}".format(e))

    return total, scannedUA


def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
Turla Kopiluwak User-Agent Shodan Search
----------------------------------------------------------------
This tool will perform a regex search over user-agents in Shodan looking for the unique Kopiluwak string appended to the end.

To use, just include your Shodan API token as a parameter.

Examples:
\t python kopiluwakUAShodanSearch.py -t Shodan API Token
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-t", "--token", help="Shodan API Token")

    args = parser.parse_args()

    if args.token:
        print("%s\nTurla Kopiluwak User-Agent Shodan Search\n" % (logo))
        total, scannedUA = uaShodanCheck(
            "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64)", args.token
        )
        print("Scanned %s User-Agents, results are below: \n" % (total))
        for ua, info in scannedUA.items():
            ip = info[1]
            print("Scanned:%s\n\tIP: %s\n\tResult:%s\n" % (ua, info[0], info[1]))
    else:
        print(
            'Error: Please Provide Shodan API Token as a parameter, "python kopiluwakUAShodanSearch.py -t Shodan API Token"'
        )


if __name__ == "__main__":
    main()
