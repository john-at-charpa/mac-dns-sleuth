# Mac DNS Sleuth Help

## Overview

Mac DNS Sleuth is a DNS diagnostics and email security validation utility for macOS.

It helps users investigate DNS records and validate technologies such as SPF, DMARC, BIMI, DNSSEC, MTA-STS, SMTP TLS, and MX configuration.

Results can be viewed directly in the application, copied to the clipboard, or saved to a text file.

---

## Performing a Lookup

1. Enter a domain name.
2. Select a DNS server or use **System Default**.
3. Enable the desired DNS type checks.
4. Click **Check**.
5. Review the results.

Individual checks may be enabled or disabled depending on your requirements.

---

## DNS Servers

Mac DNS Sleuth supports the following DNS resolvers by default:

- System Default
- Cloudflare
- Google
- Quad9

Additional DNS servers may be added using the configuration file.

The selected DNS server is used for all DNS-based validation performed by the application.

---

## Custom Queries

The **Custom Query** feature allows arbitrary DNS lookups.

Specify a hostname and record type, then click **Run Custom Query**.

Supported record types include:

- A
- AAAA
- CAA
- CNAME
- MX
- NS
- PTR
- SRV
- TLSA
- TXT

Custom queries are useful when troubleshooting records that are not covered by the built-in validation checks. Custom record types can be manually entered into the type box.

---

## Saving Results

The **Save TXT** button saves the current results to a text file.

---

## Copying Results

Mac DNS Sleuth provides multiple copy functions.

- **Copy** buttons copy individual records or sections.
- **Copy All** copies the complete result output.

Copied data is placed on the macOS clipboard.

---

## Configuration File

Application settings are stored in:

`~/Library/Application Support/Mac DNS Sleuth/mac-dns-sleuth.conf`

The configuration file contains:

- Default check selections
- DNS server definitions
- Debug logging settings

The configuration file can be opened from:

**Mac DNS Sleuth → Open Config File**

Changes take effect the next time the application is started.

---

## Log File

When debug logging is enabled, application logs are written to:

`~/Library/Logs/mac-dns-sleuth.log`

The log file can be opened from:

**Mac DNS Sleuth → Open Log File**

---

## Understanding the Results

Many DNS and email-security technologies work together.

For example:

- SPF identifies authorized mail senders.
- DKIM verifies message signatures.
- DMARC provides policy and reporting based on SPF and DKIM alignment.
- BIMI allows approved logos to be displayed by participating mail clients.
- DNSSEC protects DNS responses against tampering.
- MTA-STS and SMTP TLS help secure mail transport.

---

## About Checkdmarc

Mac DNS Sleuth uses the open-source **checkdmarc** project for DNS and email-security validation. Many thanks to Sean Whalen for doing the heavy lifting.

https://github.com/domainaware/checkdmarc

Additional functionality is provided by the Mac DNS Sleuth user interface and helper components.

---

## Troubleshooting

### No Results Returned

Verify that:

- The domain name is valid.
- You have network connectivity.
- The selected DNS server is reachable.

### Lookup Appears Slow

Some checks require additional DNS lookups, HTTPS requests, SMTP connections, or WHOIS queries.

Response times are dependent on the remote services being queried.

### Unexpected Results

Try:

- Using a different DNS server.
- Running a Custom Query.
- Comparing results against external DNS tools.

---

## License

Mac DNS Sleuth is licensed under the BSD 3-Clause License.

See the About box for version information and included components.
