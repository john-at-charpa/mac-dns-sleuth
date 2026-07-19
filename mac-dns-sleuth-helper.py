#!/usr/bin/env python

import sys
import json
import subprocess
import dns.resolver

from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

from checkdmarc.bimi import check_bimi
from checkdmarc.dmarc import check_dmarc
from checkdmarc.dnssec import test_dnssec
from checkdmarc.mta_sts import check_mta_sts
from checkdmarc.smtp import (
    test_starttls,
    test_tls,
)
from checkdmarc.utils import (
    get_nameservers,
    get_mx_records,
    get_a_records,
    get_reverse_dns,
)
from checkdmarc.dnssec import (
    test_dnssec,
    get_tlsa_records,
)
from checkdmarc.soa import check_soa
from checkdmarc.spf import check_spf
from checkdmarc.utils import get_nameservers

# ----------------------------------------------------------------------
# Debug
# ----------------------------------------------------------------------

DEBUG = False
def debug(msg):
    if DEBUG:
        print(msg, file=sys.stderr, flush=True)

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def run_check(result, name, func, *args, **kwargs):
    try:
        result[name] = func(*args, **kwargs)
    except Exception as e:
        result[name] = {
            "error": str(e)
        }

def get_resolver(nameservers=None):

    resolver = dns.resolver.Resolver()

    if nameservers:
        resolver.nameservers = nameservers

    return resolver

# ----------------------------------------------------------------------
# Custom Checks
# ----------------------------------------------------------------------

def check_query(
    name,
    record_type,
    nameservers=None
):

    resolver = get_resolver(nameservers)

    answers = resolver.resolve(
        name,
        record_type
    )

    return {
        "name": name,
        "type": record_type,
        "results": [str(answer) for answer in answers]
    }

def check_mx_fast(
    domain,
    nameservers=None,
    skip_tls=False
):
    hosts = []
    warnings = []

    mx_records = get_mx_records(
        domain,
        nameservers=nameservers
    )

    for record in mx_records:

        hostname = (
            record["hostname"]
                .lower()
        )

        host = {
            "preference":
                record["preference"],
            "hostname":
                hostname,
            "addresses": [],
        }

        try:
            addresses = get_a_records(
                hostname,
                nameservers=nameservers
            )

            host["addresses"] = addresses

            tlsa_records = get_tlsa_records(
                hostname,
                nameservers=nameservers
            )

            if tlsa_records:
                host["tlsa"] = tlsa_records

            if not addresses:
                warnings.append(
                    f"{hostname} has no "
                    "A or AAAA records"
                )

        except Exception as e:
            warnings.append(
                f"{hostname}: {e}"
            )

        hosts.append(host)

    return {
        "hosts": hosts,
        "warnings": warnings,
    }

def check_proofpoint(
    domain,
    nameservers=None
):

    try:
        resolver = get_resolver(nameservers)

        answers = resolver.resolve(
            f"_proofpoint-verification.{domain}",
            "TXT"
        )

        values = []

        for answer in answers:
            values.append(
                "".join(
                    x.decode()
                    if isinstance(x, bytes)
                    else str(x)
                    for x in answer.strings
                )
            )

        return {
            "valid": True,
            "records": values
        }

    except Exception as e:

        return {
            "valid": False,
            "error": str(e)
        }


def check_whois(domain):

    result = subprocess.run(
        ["/usr/bin/whois", domain],
        capture_output=True,
        text=True
    )

    return {
        "raw": result.stdout
    }

def daemon_loop():

    while True:

        line = sys.stdin.readline()

        if not line:
            break

        try:

            request = json.loads(line)

            debug(f"REQUEST={request}")

            response = process_request(request)

            debug(f"RESPONSE={response}")

            print(json.dumps(response))

            sys.stdout.flush()

        except Exception as e:

            print(json.dumps({
                "error": str(e)
            }))

            sys.stdout.flush()

def process_request(request):

    domain = request.get("domain")

    nameservers = request.get("nameservers")

    debug(f"NAMESERVERS={nameservers}")

    result = {}

    if domain:
        result["domain"] = domain

    jobs = []

    if request.get("query_name") and request.get("query_type"):
        jobs.append(
            (
                "query",
                check_query,
                (
                    request["query_name"],
                    request["query_type"],
                ),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("dnssec"):
        jobs.append(
            (
                "dnssec",
                test_dnssec,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("spf"):
        jobs.append(
            (
                "spf",
                check_spf,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("dmarc"):
        jobs.append(
            (
                "dmarc",
                check_dmarc,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("soa"):
        jobs.append(
            (
                "soa",
                check_soa,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("nameserver"):
        jobs.append(
            (
                "nameserver",
                get_nameservers,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("mta_sts"):
        jobs.append(
            (
                "mta_sts",
                check_mta_sts,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("bimi"):
        jobs.append(
            (
                "bimi",
                check_bimi,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("mx"):
        jobs.append(
            (
                "mx",
                check_mx_fast,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("proofpoint"):
        jobs.append(
            (
                "proofpoint",
                check_proofpoint,
                (domain,),
                {
                    "nameservers": nameservers,
                },
            )
        )

    if request.get("whois"):
        jobs.append(
            (
                "whois",
                check_whois,
                (domain,),
                {},
            )
        )

    with ThreadPoolExecutor(
        max_workers=max(1, len(jobs))
    ) as executor:

        futures = {}

        for (
            name,
            func,
            args,
            kwargs,
        ) in jobs:

            future = executor.submit(
                func,
                *args,
                **kwargs
            )

            futures[future] = name

        for future in as_completed(futures):

            name = futures[future]

            try:

                result[name] = future.result()

            except Exception as e:

                result[name] = {
                    "error": str(e)
                }

    return result

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():

    if "--daemon" in sys.argv:
        daemon_loop()
        return

    query_name = None
    query_type = None

    if "--query-name" in sys.argv:
        idx = sys.argv.index("--query-name")
        query_name = sys.argv[idx + 1]

    if "--query-type" in sys.argv:
        idx = sys.argv.index("--query-type")
        query_type = sys.argv[idx + 1]

    domain = None

    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        domain = sys.argv[1]

    for arg in sys.argv[1:]:

        if arg.startswith("--"):
            continue

        if arg == query_name:
            continue

        if arg == query_type:
            continue

        domain = arg
        break

    if not domain and not (query_name and query_type):
        print(json.dumps({
            "error": (
                "usage: dns-sleuth-helper.py "
                "<domain> or --query-name/--query-type"
            )
        }))
        sys.exit(1)

    request = {
        "domain": domain,
        "query_name": query_name,
        "query_type": query_type,
        "dnssec": "--dnssec" in sys.argv,
        "spf": "--spf" in sys.argv,
        "dmarc": "--dmarc" in sys.argv,
        "bimi": "--bimi" in sys.argv,
        "mx": "--mx" in sys.argv,
        "mta_sts": "--mta-sts" in sys.argv,
        "smtp_tls": "--smtp-tls" in sys.argv,
        "soa": "--soa" in sys.argv,
        "nameserver": "--nameserver" in sys.argv,
        "proofpoint": "--proofpoint" in sys.argv,
        "whois": "--whois" in sys.argv,
    }

    result = process_request(request)

    print(
        json.dumps(
            result,
            indent=2,
            default=str
        )
    )

if __name__ == "__main__":
    main()
