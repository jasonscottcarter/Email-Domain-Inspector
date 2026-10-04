# Email Domain Inspector

A local Node.js web app that inspects the email infrastructure of any domain or mail server IP, using free public DNS. No API keys required.


## Features

For a domain, it checks:

- **MX:** mail exchangers sorted by priority
- **SPF:** the full record plus a plain-language reading of the policy (hard fail, softfail, neutral, or pass-all)
- **DKIM:** tries a built-in list of common selectors (Microsoft 365, Google Workspace, Mimecast, Proofpoint, and generic names) and reports which ones exist
- **DMARC:** policy, subdomain policy, enforcement percentage, alignment modes, and report destinations
- **BIMI:** the logo and authority URLs
- **MTA-STS:** the DNS record plus the hosted policy file (mode, max age, allowed MX hosts)
- **TLS-RPT:** where TLS failure reports are sent
- **Blocklists:** checks the IP of the highest-priority MX host against a list of public DNS blocklists

For a mail server IP, it checks the address against the same blocklists.

Everything uses DNS queries and Node's built-in `https` module. Express is the only dependency.

<!-- Add a screenshot made from a public domain, e.g.: ![Dashboard](docs/screenshot.png) -->

## Prerequisites

- [Node.js](https://nodejs.org) v18 or later (LTS). Verify with `node --version`
- [Git](https://git-scm.com). Verify with `git --version`
- A code editor such as [VS Code](https://code.visualstudio.com) (optional)

## Installation

```bash
git clone https://github.com/jasonscottcarter/email-inspector.git
cd email-inspector
npm install
node server.js
```

You should see `Email Inspector running at http://localhost:3000`. Open that address in your browser. Press `Ctrl+C` in the terminal to stop the server.

## Usage

Enter a bare domain (for example `gmail.com`) or an IPv4 address (for example `74.125.141.27`) and click **Inspect**. The tool detects which one you entered and runs the matching checks.

| Input | Returns |
| --- | --- |
| Domain | MX, SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, and a blocklist check on the first MX host's IP |
| IPv4 address | Blocklist check |

## What each check tells you

| Check | What it shows |
| --- | --- |
| MX | Mail exchanger hostnames and priorities. Lower priority is preferred. |
| SPF | Which servers may send for the domain, and how strictly receivers should treat others. |
| DKIM | Which common selectors publish a signing key. |
| DMARC | What receivers should do with mail that fails SPF and DKIM alignment, and where reports go. |
| BIMI | Brand logo and certificate URLs used by supporting mail clients. |
| MTA-STS | Whether the domain requires encrypted delivery and which MX hosts are allowed. |
| TLS-RPT | Where reports about failed encrypted deliveries are sent. |
| Blocklists | Whether the mail server IP appears on public DNS blocklists. |

## Project structure

```
email-inspector/
├── public/
│   └── index.html     # Frontend dashboard
├── .gitignore
├── package.json
├── package-lock.json
└── server.js          # Express backend and all DNS logic
```

## Limitations

- **DKIM selectors can't be fully discovered.** DNS has no way to list a domain's selectors, so only selectors in the built-in list are found. A domain using a custom selector will show no DKIM result. This is expected.
- **Records are checked at the exact name entered.** A subdomain such as `mail.example.com` will show no DMARC or BIMI record even if the parent domain publishes one that applies.
- **Blocklist results need care.** The tool treats any answer from a blocklist as a listing and any failed lookup as "not listed". Some blocklists refuse queries from public resolvers, and some zones in the list may no longer be active (SORBS, for example, shut down in June 2024). Review the `RBLS` list in `server.js` and prefer a local resolver for dependable results.
- **IPv4 only** for the blocklist checks and IP input.
- **Only the highest-priority MX host** is checked against blocklists.

## Security notes

- **Run it locally only.** The server has no authentication and listens on port 3000. Use it on a trusted machine and network, and don't expose the port to the internet.
- **Domains you inspect control the data you see.** DNS records, BIMI logo URLs, and MTA-STS policies come from the domain owner. Be cautious when inspecting domains you suspect are malicious.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `node: command not found` | Node.js isn't installed or isn't on your PATH. Reinstall it and open a new terminal. |
| `Cannot find module 'express'` | Run `npm install` from inside the `email-inspector` folder. |
| Port 3000 already in use | Change `3000` to `3001` at the bottom of `server.js`, restart, and open `http://localhost:3001`. |
| Every blocklist shows "not listed" | Your network or resolver may be blocking queries to blocklist zones. Try a different network or DNS server. |
| MTA-STS policy not fetched | The domain has an MTA-STS DNS record but its policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` is unreachable. This is a configuration issue on the domain owner's side. |

## Built with

Node.js, Express, Node's built-in `dns` and `https` modules, and vanilla JavaScript.

## License

MIT. See [LICENSE](LICENSE).
