# DNS Glossary

## A Record

Maps a hostname to an IPv4 address.

Example:

`example.com → 93.184.216.34`

More Information:

https://en.wikipedia.org/wiki/A_record

---

## AAAA Record

Maps a hostname to an IPv6 address.

Example:

`example.com → 2606:2800:220:1:248:1893:25c8:1946`

More Information:

https://en.wikipedia.org/wiki/AAAA_record

---

## BIMI

**Brand Indicators for Message Identification**

Allows approved senders to associate a brand logo with authenticated email messages.

BIMI works alongside SPF, DKIM, and DMARC to improve trust in email and increase brand recognition.

More Information:

https://en.wikipedia.org/wiki/Brand_Indicators_for_Message_Identification

---

## CAA

**Certification Authority Authorization**

Specifies which certificate authorities are permitted to issue TLS certificates for a domain.

CAA records help reduce the risk of unauthorized certificate issuance.

More Information:

https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization

---

## CNAME

**Canonical Name**

Creates an alias from one hostname to another hostname.

For example, a service hostname may point to a provider-managed hostname instead of directly to an IP address.

More Information:

https://en.wikipedia.org/wiki/CNAME_record

---

## SPF

**Sender Policy Framework**

Defines which systems are authorized to send email on behalf of a domain.

Receiving mail systems use SPF to help determine whether a message originates from an authorized source.

SPF validates the sending infrastructure but does not validate message content.

More Information:

https://en.wikipedia.org/wiki/Sender_Policy_Framework

---

## DKIM

**DomainKeys Identified Mail**

Adds a cryptographic signature to email messages.

DKIM allows recipients to verify that a message was authorized by the sending domain and that the content has not been modified after signing.

More Information:

https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail

---

## DMARC

**Domain-based Message Authentication, Reporting and Conformance**

Provides policy and reporting for email authentication.

DMARC builds upon SPF and DKIM by validating alignment between authenticated identifiers and the visible sender domain.

It allows domain owners to specify how authentication failures should be handled and provides reporting on message authentication activity.

In simple terms:

- SPF verifies the sender's infrastructure.
- DKIM verifies the message signature.
- DMARC uses SPF and/or DKIM alignment to determine whether a message should be trusted.

More Information:

https://en.wikipedia.org/wiki/DMARC

---

## DNSSEC

**Domain Name System Security Extensions**

Protects DNS responses using cryptographic signatures.

DNSSEC helps prevent DNS spoofing and other forms of DNS manipulation.

More Information:

https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions

---

## MTA-STS

**Mail Transfer Agent Strict Transport Security**

Allows mail domains to publish a policy requiring encrypted SMTP transport.

MTA-STS helps protect email against downgrade attacks and misconfigured mail routing.

More Information:

https://en.wikipedia.org/wiki/MTA-STS

---

## MX

**Mail Exchange Record**

Specifies which mail servers are responsible for receiving email for a domain.

A domain may publish multiple MX records for redundancy and failover.

More Information:

https://en.wikipedia.org/wiki/MX_record

---

## NS

**Name Server Record**

Identifies the authoritative DNS servers for a domain.

These servers are responsible for providing DNS answers for the zone.

More Information:

https://en.wikipedia.org/wiki/Name_server

---

## PTR

**Pointer Record**

Provides reverse DNS lookups by mapping IP addresses to hostnames.

PTR records are commonly used for mail server validation and troubleshooting.

More Information:

https://en.wikipedia.org/wiki/PTR_record

---

## Proofpoint Verification

Proofpoint products commonly use TXT records to verify ownership and control of a domain.

These records are frequently required when onboarding a domain into a Proofpoint service.

More Information:

https://www.proofpoint.com/us/threat-reference/email-authentication

---

## SOA

**Start of Authority Record**

Contains important information about a DNS zone including the primary nameserver, serial number, and zone timers.

SOA records are used by secondary DNS servers to track zone updates.

More Information:

https://en.wikipedia.org/wiki/SOA_record

---

## SRV

**Service Record**

Specifies the hostname and port associated with a network service.

Many applications use SRV records to locate services automatically.

More Information:

https://en.wikipedia.org/wiki/SRV_record

---

## SMTP TLS Reporting

**SMTP TLS Reporting (TLS-RPT)**

Provides reports about successful and failed SMTP TLS connections.

Organizations use these reports to identify encryption problems affecting email delivery.

More Information:

https://en.wikipedia.org/wiki/SMTP_TLS_Reporting

---

## TLSA

**Transport Layer Security Authentication**

A DNS record used by DANE to publish certificate or public-key information.

TLSA records are typically used in conjunction with DNSSEC.

More Information:

https://en.wikipedia.org/wiki/TLSA

---

## TXT

A free-form DNS text record.

TXT records are commonly used for SPF, DKIM, DMARC, BIMI, Proofpoint verification, and many other validation or security mechanisms.

More Information:

https://en.wikipedia.org/wiki/TXT_record

---

## WHOIS

A protocol used to obtain domain registration information.

WHOIS records often include registrar information, registration dates, expiration dates, and other administrative details.

More Information:

https://en.wikipedia.org/wiki/WHOIS
