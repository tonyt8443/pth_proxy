## pth_proxy

Pass the Hash NTLM HTTP Proxy (pth_proxy.py) to authenticate to Web Application

- Use where password is not available but NT hash is available
- PTH proxy (pth_proxy.py) intercepts HTTP requests and uses the provided NT hash to inject the NTLM authentication headers to the target web application


### How it works

pth_proxy allows authentication to web application using a NT hash

- Listens on 127.0.0.1:3128 (or whatever you pass)
- CONNECT host:443 → replies 200 Connection established, then TLS-terminates using a leaf cert signed by an ephemeral CA it just generated.
- TLS now ends at the proxy and allows NTLM Authorization header to be injected inside the tunnel.
- Plain HTTP requests (absolute URI in the request line, the classic proxy format) are forwarded directly.
- For each request, a requests.Session with HttpNtlmAuth (identity, "LM:NT") is used to talk to the real target
- requests-ntlm recognises the LM:NT form and builds the NTLM Type 3 message from the hash, no plaintext needed.
- The response is written back to the client over the encrypted tunnel, after stripping hop-by-hop headers and forcing Content-Length (since requests has already decompressed the body).
- The CA cert and per-host leaf certs are generated on demand into a temp directory and printed at startup.

*Use only in environments where you have explicit authorisation such as CTFs*

### Example Usage

Start NTLM proxy authenticating with provided NT hash to DOMAIN
```
$ python3 pth_proxy.py --user john --domain DOMAIN --hash 8bf305c62b55c9def1c5c30fb24ff2b8
```
Use curl to website using an NTLM hash
```
$ curl -v --insecure --proxy http://127.0.0.1:3128 https://target.domain.example/
```

