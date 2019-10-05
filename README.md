
# fimeier-acme-project-netsec-fall-19
Deadline: 8.11.2019 23:59


- [fimeier-acme-project-netsec-fall-19](#fimeier-acme-project-netsec-fall-19)
- [ACMEv2 (stuff extracted from https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md)](#acmev2-stuff-extracted-from-httpsgithubcomietf-wg-acmeacmeblobmasterdraft-ietf-acme-acmemd)
  - [Encoding](#encoding)
- [Message Transport](#message-transport)
  - [HTTPS Requests](#https-requests)
- [Terminology](#terminology)


# ACMEv2 (stuff extracted from https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md)
## Encoding
* All requests and responses sent via HTTP by ACME clients, ACME servers, and validation servers as well as any inputs for digest computations MUST be encoded using the UTF-8 character set {{!RFC3629}}. Note that identifiers that appear in certificates may have their own encoding considerations (e.g., DNS names containing non-ASCII characters are expressed as A-labels rather than U-labels). Any such encoding considerations are to be applied prior to the aforementioned UTF-8 encoding.
# Message Transport
* between an ACME client and an ACME server are done over HTTPS, using JSON Web Signature (JWS) RFC7515 https://tools.ietf.org/html/rfc7515
* HTTPS provides server authentication and confidentiality
* With some ACME-specific extensions, JWS provides authentication of the client's request payloads, anti-replay protection, and integrity for the HTTPS request URL

## HTTPS Requests
* Each ACME function is accomplished by the client sending a sequence of HTTPS requests to the server {{!RFC2818}}, carrying JSON messages {{!RFC8259}}. Use of HTTPS is REQUIRED.
* **Normal-setting:** the ACME client is the HTTPS client and the ACME server is the HTTPS server.
* **Exceptions:** The ACME server acts as a client when **validating challenges**:
  * an HTTP client when validating an 'http-01' challenge, a DNS client with 'dns-01', etc.
* the ACME protocol itself includes anti-replay protections in all cases where they are required. For this reason, there are **no restrictions on what ACME data can be carried in 0-RTT.**
* ACME clients
  * **MUST send a User-Agent header field**, in accordance with {{!RFC7231}}. This header field SHOULD include the name and version of the ACME software in addition to the name and version of the underlying HTTP client software.
  * **SHOULD send an Accept-Language header field **in accordance with {{!RFC7231}} to enable localization of error messages.





























# Terminology
copied from https://www.ietf.org/rfc/rfc2119.txt
1. **MUST**   This word, or the terms "REQUIRED" or "SHALL", mean that the
   definition is an absolute requirement of the specification.

2. **MUST NOT**   This phrase, or the phrase "SHALL NOT", mean that the
   definition is an absolute prohibition of the specification.

3. **SHOULD**   This word, or the adjective "RECOMMENDED", mean that there
   may exist valid reasons in particular circumstances to ignore a
   particular item, but the full implications must be understood and
   carefully weighed before choosing a different course.

4. **SHOULD NOT**   This phrase, or the phrase "NOT RECOMMENDED" mean that
   there may exist valid reasons in particular circumstances when the
   particular behavior is acceptable or even useful, but the full
   implications should be understood and the case carefully weighed
   before implementing any behavior described with this label.

5. **MAY**   This word, or the adjective "OPTIONAL", mean that an item is
   truly optional.  One vendor may choose to include the item because a
   particular marketplace requires it or because the vendor feels that
   it enhances the product while another vendor may omit the same item.
   An implementation which does not include a particular option MUST be
   prepared to interoperate with another implementation which does
   include the option, though perhaps with reduced functionality. In the
   same vein an implementation which does include a particular option
   MUST be prepared to interoperate with another implementation which
   does not include the option (except, of course, for the feature the
   option provides.)