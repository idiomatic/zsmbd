# References

The specifications that shaped zsmbd, with local copies in [docs/references](docs/references/). Copies were retrieved on 2026-10-31; the Microsoft documents are the current release on that date. Where a copy and the code disagree, check the online version for errata.

## SMB and file system

| Document | Local copy | Used for |
|---|---|---|
| [MS-SMB2]: Server Message Block Protocol Versions 2 and 3 | [MS-SMB2.pdf](docs/references/MS-SMB2.pdf) | Message formats, dialects, signing, encryption, key derivation, credits, and every command (`smb/proto.zig`, `smb/conn.zig`, `smb/files.zig`) |
| [MS-FSCC]: File System Control Codes | [MS-FSCC.pdf](docs/references/MS-FSCC.pdf) | Information classes, FSCTLs, attributes, and directory entries (`smb/files.zig`) |
| [MS-ERREF]: Windows Error Codes | [MS-ERREF.pdf](docs/references/MS-ERREF.pdf) | NTSTATUS values (`smb/proto.zig`, `smb/vfs.zig`) |
| [MS-DTYP]: Windows Data Types | [MS-DTYP.pdf](docs/references/MS-DTYP.pdf) | FILETIME, SIDs, ACLs, and security descriptors (`smb/files.zig`) |

## Authentication

| Document | Local copy | Used for |
|---|---|---|
| [MS-NLMP]: NT LAN Manager Authentication Protocol | [MS-NLMP.pdf](docs/references/MS-NLMP.pdf) | NTLMv2, the NT hash, MIC, and the section 4.2.4 test vectors (`smb/auth/ntlm.zig`) |
| [MS-SPNG]: SPNEGO Extension | [MS-SPNG.pdf](docs/references/MS-SPNG.pdf) | Windows SPNEGO behavior (`smb/auth/spnego.zig`) |
| RFC 4178: SPNEGO | [rfc4178.txt](docs/references/rfc4178.txt) | NegTokenInit, NegTokenResp, and mechListMIC (`smb/auth/spnego.zig`) |
| RFC 1320: MD4 | [rfc1320.txt](docs/references/rfc1320.txt) | MD4 for NT hashes (`shared/crypto.zig`) |
| RFC 2104: HMAC | [rfc2104.txt](docs/references/rfc2104.txt) | HMAC-MD5 (NTLMv2) and HMAC-SHA256 (KDF) |

## Cryptography

| Document | Local copy | Used for |
|---|---|---|
| NIST SP 800-108r1: Key Derivation Using Pseudorandom Functions | [NIST.SP.800-108r1.pdf](docs/references/NIST.SP.800-108r1.pdf) | SMB 3 key derivation, counter mode (`shared/crypto.zig`) |
| NIST SP 800-38C: CCM Mode | [NIST.SP.800-38C.pdf](docs/references/NIST.SP.800-38C.pdf) | AES-128-CCM with SMB's 11-byte nonce (`shared/crypto.zig`) |
| NIST SP 800-38D: GCM Mode | [NIST.SP.800-38D.pdf](docs/references/NIST.SP.800-38D.pdf) | AES-128-GCM encryption (`smb/conn.zig`) |
| RFC 4493: AES-CMAC | [rfc4493.txt](docs/references/rfc4493.txt) | SMB 3 signing (`shared/crypto.zig`) |
| RFC 9106: Argon2 | [rfc9106.txt](docs/references/rfc9106.txt) | Web password hashing, argon2id (`policy/auth.zig`) |

## RPC

| Document | Local copy | Used for |
|---|---|---|
| [MS-SRVS]: Server Service Remote Protocol | [MS-SRVS.pdf](docs/references/MS-SRVS.pdf) | NetrShareEnum and NetrShareGetInfo (`smb/rpc.zig`) |
| [MS-RPCE]: RPC Protocol Extensions | [MS-RPCE.pdf](docs/references/MS-RPCE.pdf) | Bind-time feature negotiation and Windows DCE/RPC behavior (`smb/rpc.zig`) |
| [C706: DCE 1.1 RPC](https://pubs.opengroup.org/onlinepubs/9629399/) | none (The Open Group's terms) | PDU formats and NDR encoding (`smb/rpc.zig`) |

## Admin web server

| Document | Local copy | Used for |
|---|---|---|
| RFC 9110: HTTP Semantics | [rfc9110.txt](docs/references/rfc9110.txt) | Methods and status codes (`web/server.zig`) |
| RFC 9112: HTTP/1.1 | [rfc9112.txt](docs/references/rfc9112.txt) | Message framing (through `std.http`) |
| RFC 6265: HTTP State Management (cookies) | [rfc6265.txt](docs/references/rfc6265.txt) | Session cookie attributes (`web/server.zig`) |

## Sources and terms

- Microsoft Open Specifications: <https://learn.microsoft.com/openspecs/windows_protocols/>. Microsoft's intellectual property notice in each document permits copies for implementing the protocols.
- RFCs: <https://www.rfc-editor.org/>, under the IETF Trust's legal provisions.
- NIST Special Publications: <https://csrc.nist.gov/publications/sp>, works of the U.S. government.

When a new specification influences the code, add its copy here and a row above.
