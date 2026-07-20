## Mac DNS Sleuth

![Swift](https://img.shields.io/badge/swift-6.0%2B-orange?t&logoColor=white)
![mac](https://img.shields.io/badge/macOS-14%2B-blue?logo=apple&logoColor=white)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/license/BSD-3-Clause)

*A macOS application for DNS lookups and email authentication validation.*

Mac DNS Sleuth is a native SwiftUI application built around the `checkdmarc` 
project. It lets you query DNS records and validate modern email authentication
and security configurations, including technologies like SPF, DMARC, and 
MTA-STS -- all through a simple graphical interface.

This tool was primarily developed as an experiment to see if I could build a
desktop macOS application using Swift. Having grown up using Compact Macs in
the 80s and 90s, I've given it a slight System 6/7 feel as a tribute.

<p align="center">
<img src=mac-dns-sleuth-1.0-screenshot.png alt="Mac DNS Sleuth" width="823")
</p>

## Features

- DNS lookups, inspection, and custom queries
- SPF, DKIM, DMARC, BIMI, and MTA-STS validation
- DNSSEC, MX, SOA, nameserver, and WHOIS analysis
- Proofpoint verification checks
- Configurable DNS providers
- Built-in Help and DNS glossary
- Copy-to-clipboard support
- Local logging and debugging

## Requirements

Mac DNS Sleuth is intended for modern versions of macOS and has been tested
on macOS Tahoe (26) and macOS Sequoia (15). It will likely run on macOS 
Sonoma (14) as well.

Required for building:

- macOS 14 or later
- Swift 6 or later
- Python 3.10 or later
- Pip 
- The modules listed in requirements.txt (includes checkdmarc)

The application relies on a helper process built from the bundled Python code.

## Building

Build script is included that performs all required building and packaging.

```bash
./build.sh -b
```

The build process:

- Builds the helper executable
- Builds the main executable
- Copies application resources
- Generates the application bundle
- Creates a runnable `.app`

See the script's help (-h) for detailed usage.

After a successful build:

```text
Mac DNS Sleuth.app
```

will be available in the main directory.

## Configuration

A simple configuration file is created automatically on first launch
and is stored in:

```text
~/Library/Application Support/Mac DNS Sleuth/mac-dns-sleuth.conf
```

Default configuration:

```json
{
  "debug": false,
  "defaultChecks": {
    "dnssec": false,
    "spf": true,
    "dmarc": true,
    "bimi": true,
    "mx": true,
    "mtaSts": true,
    "smtpTls": false,
    "soa": true,
    "nameserver": true,
    "proofpoint": true,
    "whois": true
  }
}
```

DNS servers can be customized by modifying the dnsServers stanza.

Example:

```json
"dnsServers": {
  "System Default": "",
  "Cloudflare": "1.1.1.1,1.0.0.1",
  "Google": "8.8.8.8,8.8.4.4",
  "Quad9": "9.9.9.9,149.112.112.112"
}
```

## Logging

When debug logging is enabled via the configuration file:

```json
"debug": true
```

logs are written to:

```text
~/Library/Logs/mac-dns-sleuth.log
```

The log file is automatically rotated when it exceeds 5 MB.

## Basic Usage

Launch:

```text
Mac DNS Sleuth.app
```

Enter a domain name:

```text
example.com
```

Select the desired checks and click:

```text
Check
```

Results are displayed in structured sections for:

- SPF
- DMARC
- BIMI
- DNSSEC
- MX
- MTA-STS
- Nameservers
- SOA
- WHOIS
- Proofpoint Verification
- Custom Queries

Individual records may be copied directly from the interface or saved to disk.

## Custom Queries

Mac DNS Sleuth also supports arbitrary DNS lookups.

Example:

```text
Record:
    _dmarc.example.com

Type:
    TXT
```

or:

```text
Record:
    selector1._domainkey.example.com

Type:
    TXT
```

Supported record types include:

```text
TXT
A
AAAA
CNAME
MX
NS
PTR
SRV
CAA
TLSA
```

## Documentation

The application includes:

```text
Help
DNS Glossary
```

Both documents are stored as Markdown and bundled directly into the
application.

## Technologies Used

- Swift
- SwiftUI
- AppKit
- Python
- checkdmarc

## macOS Gatekeeper

The Mac DNS Sleuth binary builds are currently distributed as unsigned 
applications. Due to this, macOS Gatekeeper may prevent them from launching.

If you prefer to use the binaries instead of compiling from source, then 
you can optionally remove the quarantine attribute before running it:

```sh
xattr -rd com.apple.quarantine "Mac DNS Sleuth.app"
```

If it still won't launch, then you can clear all extended attributes:

```sh
xattr -cr "Mac DNS Sleuth.app"
```

## License

Licensed under the BSD 3-Clause License.

## Credits

Mac DNS Sleuth is built on the excellent *checkdmarc* project by Sean Whalen and contributors.

<https://github.com/domainaware/checkdmarc>

## Author

John Wood <https://github.com/john-at-charpa>
