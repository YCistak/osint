# osint

Terminal OSINT toolkit: username search across **500 sites**, email, domain/IP, GitHub and phone recon, a privacy self-audit with a 0-100 score, and a private password check, in an interactive shell or as one-shot commands.

![osint banner and a sample scan](docs/screenshot.svg)

> Use it on yourself, in CTFs, or with explicit authorization. See [Legal and ethics](#legal-and-ethics).

## Features

- **Category menu**: start `osint`, pick a number (Username, Email, Domain/IP, Phone, Image, GitHub, Me, Password), type just the target. Power users can still type `username torvalds` from the main prompt.
- **Username search** on 500 sites. The site list is derived from [maigret](https://github.com/soxoj/maigret)'s database and pruned against the live internet: every shipped site was checked with random nonsense usernames and none reports a false "found".
- **Profile details** under each found account: name, bio, location, company, website, avatar. Site-specific parsers for GitHub, GitLab, Bluesky, Keybase, Reddit, Hacker News and DEV, plus an `og:` meta-tag fallback that reuses the page already downloaded.
- **Email recon** with free sources and no API keys: XposedOrNot breaches, [holehe](https://github.com/megadose/holehe) account checks, Gravatar and GitHub profiles, MX and mail provider detection.
- **Chained scans**: usernames found in email results (GitHub login, Gravatar username, email local part) can be searched right away (`Scan these usernames? [y/N]`, or `--chain` in one-shot mode) with a combined summary.
- **Domain / IP recon**: whois, DNS records, subdomains from certificate transparency (crt.sh), reverse DNS and geolocation for IPs.
- **Domain security** (domains): SPF and DMARC with a short assessment, common DKIM selectors, open ports / hostnames / known CVEs from Shodan InternetDB for the resolved A records, the TLS certificate (issuer, subject, SANs, validity, days left) and the Wayback Machine history (first and last snapshot). Each part is its own section and fails on its own.
- **Me (privacy self-audit)**: give any of a username, an email address and a phone number; it runs the relevant scans and prints accounts found, breaches (count, newest, exposed data classes), exposed profile fields, phone exposure, a transparent **0-100 privacy score** with a points table and concrete recommendations. Optionally checks one of your passwords (hidden prompt). Included in reports and `--json`. See [Privacy score](#privacy-score).
- **Password check**: [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API with k-anonymity. See [Password privacy](#password-privacy).
- **GitHub deep scan**: profile, repositories, top languages, stars, organizations, recent activity and the e-mail addresses exposed in public commits (real addresses are flagged, noreply ones are not). Uses the public API; set `GITHUB_TOKEN` for a higher rate limit.
- **Username variations**: `--variations` (or `variations on`, or `<name> -v`) also searches up to 10 likely variants (separators, initials, `1`, `123`, the year); the list is shown first and found profiles are de-duplicated by URL.
- **Reverse image search**: for an image URL it builds Google Lens, Yandex, Bing Visual Search and TinEye links and reads its EXIF (downloaded to a temp file, max 20 MB, content type checked, treated as data only). For a local file it prints the upload pages; the file is never uploaded by osint.
- **History**: scan summaries (never passwords) in a local SQLite file; `history`, `history show`, `history diff`, `history clear`, and a "changes since the last scan" line after each scan. `--no-history` turns it off.
- **Proxy / Tor**: `--proxy URL`, `--tor`, `OSINT_PROXY`, and `proxy <url>|tor|off` in the shell. See [Proxy and Tor](#proxy-and-tor).
- **Phone analysis**, fully offline ([phonenumbers](https://github.com/daviddrysdale/python-phonenumbers)): validity, E.164 / international format, country, region, carrier, line type, timezones. Numbers without `+` use region `TR` unless `--region` says otherwise.
- **Image metadata**: EXIF camera, date, software and GPS (decimal coordinates plus Google Maps / OpenStreetMap links) via Pillow, no exiftool needed.
- **Reports**: Markdown (`save`) or a single self-contained dark HTML page (`save --html` or a `.html` path) with clickable links and avatars. All external data is HTML-escaped.
- Interactive shell with history and context-aware tab completion, or **one-shot** commands with `--json` output.
- Ctrl-C cancels the running scan, not the program; partial results are kept.

## Install

Requires Python 3.10 or newer. The easiest way, for everyone:

```bash
pipx install git+https://github.com/YCistak/osint
# or
uv tool install git+https://github.com/YCistak/osint

osint
```

Try it without installing: `uv tool run --from git+https://github.com/YCistak/osint osint --version`.

From a clone (for development):

```bash
git clone https://github.com/YCistak/osint.git
cd osint

# with uv (recommended)
uv venv .venv && uv pip install --python .venv/bin/python -e .

# or with pip
python3 -m venv .venv && .venv/bin/pip install -e .

.venv/bin/osint
```

`./run.sh` does the same setup on first run and then starts the shell.

## Usage

### Interactive shell

```text
$ osint        # clears the terminal first, then shows the banner and the menu
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
v0.3 · 500 sites · type 'help'

  [1]   Username   search a username on 500 sites
  [2]   Email      breaches, accounts, profiles, mail server
  [3]   Domain/IP  whois, DNS, subdomains, geolocation
  [4]   Phone      country, carrier, line type
  [5]   Image      EXIF metadata & GPS
  [0]   Exit

osint ❯ 1
```

Typing `1` (or `username`) clears the screen and enters the category. The prompt becomes `osint/username ❯` and you only type the target:

```text
osint/username ❯ torvalds
```

Inside a category: the target scans, `save [path] [--html]`, `show all|found`, `back` or `0` returns to the menu, `clear`, `help`, `exit`. Tab completion follows the context (category names and numbers in the menu, flags after a target, file paths for images).

| Command (works from the main prompt too) | What it does |
|---|---|
| `username <name>` | Search a username on all sites, with profile details |
| `email <address> [--unsafe] [--all-modules]` | Breaches, registered accounts, profiles, mail server; offers to scan the discovered usernames |
| `domain <domain\|ip>` | Whois, DNS, subdomains (domain) or reverse DNS and geolocation (IP) |
| `phone <number> [--region XX]` | Offline phone number analysis |
| `image <path>` | EXIF metadata and GPS of a local image (`~` is expanded) |
| `save [path] [--html]` | Save the last result: Markdown by default, HTML with `--html` or a `.html` path (default folder `./reports/`) |
| `show all\|found` | Re-display the last result; `all` also lists not-found and unknown sites |
| `help`, `clear` | Help text, redraw the current screen |
| `exit`, `quit`, Ctrl-D | Leave (`0` at the main menu also leaves) |

Output markers: `[+]` found (green), `[-]` not found (red, hidden unless `show all`), `[?]` unknown (yellow), `[*]` info and progress (blue). Sites that could not be checked (blocked, rate limited, timeout) are counted in the summary instead of flooding the screen.

### One-shot

```bash
osint username torvalds                 # live hits, then totals
osint username torvalds --show-all      # include not found / unknown
osint email jane@example.com            # grouped sections
osint email jane@example.com --unsafe   # also run password-reset checks (see below)
osint domain example.com
osint domain 1.1.1.1
osint phone "0555 111 22 33"            # region TR by default
osint phone 650-253-0000 --region US
osint image ~/Pictures/photo.jpg        # EXIF + GPS
osint email jane@example.com --chain    # also search the usernames found in the email results
osint domain example.com --json         # machine-readable, no banner or progress
osint username torvalds --save          # also write ./reports/username-torvalds-<date>.md
osint username torvalds --save out.html # HTML report (or: --save --html)
osint --no-banner                       # shell without the banner
```

Exit codes: `0` ok, `2` invalid input, `130` scan cancelled.

### Email output

```text
[*] Breaches
[*] Registered accounts
[*] Profiles
[*] Mail server
[*] Tip: run 'username <localpart>' to search the local part as a username.
```

- **Breaches**: XposedOrNot breach list with risk score and password exposure; the terminal shows the 15 newest, reports and `--json` keep all.
- **Registered accounts**: holehe results. Three groups of holehe modules are skipped by default:
  - the 4 *password reset* modules (`adobe`, `mail_ru`, `odnoklassniki`, `samsung`) because they can trigger a real email to the target. `--unsafe` includes them.
  - adult-category modules (never run).
  - modules that never gave a usable answer in our measurements (65 of 113, see `scripts/measure_email_modules.py`). `--all-modules` includes them.
- **Profiles**: Gravatar profile (SHA-256 of the address) and GitHub user search by public email (unauthenticated, limited to 10 searches per minute).
- **Mail server**: MX records and provider detection via dnspython.

## Data sources and credits

| Source | Used for | Notes |
|---|---|---|
| [maigret](https://github.com/soxoj/maigret) (MIT) | Site database for username search | `scripts/update_sites.py` converts and prunes its `data.json`; we only read it as data and implement our own checker for its `checkType` values (`status_code`, `message`, `response_url`), `urlProbe`, `headers`, `regexCheck` and `errors` |
| [holehe](https://github.com/megadose/holehe) | Email account checks | Installed as a library |
| [XposedOrNot](https://xposedornot.com) | Breach check and analytics | Free API, no key |
| [Gravatar](https://gravatar.com) | Public profile by email hash | No key |
| GitHub search API | User lookup by public email | No key, rate limited |
| GitHub, GitLab, Bluesky, Keybase, Reddit, Hacker News, DEV APIs | Profile details | Public endpoints, no key |
| [phonenumbers](https://github.com/daviddrysdale/python-phonenumbers) | Phone analysis | Offline |
| [Pillow](https://python-pillow.org) | EXIF / GPS reading | Offline |
| [crt.sh](https://crt.sh) | Subdomains from certificate transparency | Often slow or busy |
| [ip-api.com](https://ip-api.com) | IP geolocation | Free tier, HTTP only, non-commercial use |

Thank you to the maigret maintainers and contributors: the site database is the heart of the username search.

## Keeping the site list healthy

```bash
python scripts/update_sites.py            # regenerate osint/sites.json from maigret's latest data.json
python scripts/validate_sites.py          # scan nonsense usernames + each site's known account
python scripts/validate_sites.py --write --drop-blind   # prune false positives and blind sites
```

`scripts/blocklist.txt` records every removed site so regenerating keeps the pruning.

## Development

```bash
uv pip install --python .venv/bin/python -e ".[test]"
.venv/bin/python -m pytest              # offline tests
.venv/bin/python -m pytest -m live      # tests that use the real internet
```

## Known limitations

- Profile details are best effort: only some sites expose them, the generic meta-tag fallback can pick up unrelated text, and values come from the site unverified.
- Phone carrier is the original owner of the number range; ported numbers show the old carrier. Line type and region are offline data and may lag behind reality.
- Image GPS exists only if the camera or phone wrote it; many apps strip EXIF.
- Username results are heuristics: a profile page that exists is not proof the account belongs to the person you are looking for, and some sites change their pages without notice.
- Sites behind bot protection answer "unknown" from some networks.
- holehe's coverage decays as services change; the dead-module list reflects one network at one point in time.
- GitHub's unauthenticated search allows 10 requests per minute; crt.sh and ip-api.com may throttle.

## Legal and ethics

This tool is meant for **auditing your own digital footprint, CTF competitions and authorized research**. Collecting data about other people without a lawful basis can violate privacy laws (GDPR, KVKK, CFAA and similar). You are responsible for how you use it. Do not use it for stalking, harassment or unauthorized profiling. The `--unsafe` email checks can send real password-reset emails to the target; use them only on addresses you own.

## License

MIT, see [LICENSE](LICENSE). Site data derived from maigret (MIT).
