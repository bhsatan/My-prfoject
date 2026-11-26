# SecScan — Local-First Security Posture Scanner

> **Prototype v0.1.0** — Read-only, offline-first security posture scanner for Windows and Linux.

SecScan inspects your local machine **read-only**, evaluates it against plain-language security rules, computes a **0–100 posture score**, and gives you a ranked list of issues with step-by-step fixes anyone can follow without searching the web.

---

## Core Guarantees

- **Strictly read-only**: Never modifies system settings, registry keys, or system files, and never installs or removes software. All fixes are text instructions.
- **No network in the core engine**: Zero telemetry, zero listeners, zero outbound calls, zero auto-updates. HTML reports have no external CDN links.
- **Runs without admin/root**: Checks that need elevated privileges (such as BitLocker or SMBv1 status on Windows) report `unknown` instead of guessing or crashing.
- **No false certainty**: If a check cannot be reliably performed, its status is `unknown`, never `pass`.
- **Plain language**: Every finding explains *why it matters* and *how to fix it* without jargon.

---

## Quick Start

```bash
# 1. Clone and enter the repository
git clone https://github.com/bhsatan/Sescan.git
cd Sescan

# 2. Create a virtual environment (Python 3.11+)
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux:   source .venv/bin/activate

# 3. Install SecScan
pip install -e .

# 4. Preview what will be inspected without collecting anything
secscan scan --dry-run

# 5. Run a scan (prints a permission notice and asks for confirmation)
secscan scan

# Save a JSON or self-contained HTML report
secscan scan --format json --output ./output
secscan scan --format html --output ./output

# Skip the confirmation prompt (useful for scripted local runs)
secscan scan --yes
```

### Updating SecScan

SecScan has no built-in updater, never uses the network itself, and is updated manually from the [Sescan repository](https://github.com/bhsatan/Sescan).

From an existing checkout (run one command per line so it works in both Linux shells and Windows PowerShell 5.1):

```bash
cd /path/to/Sescan
git fetch origin
git log HEAD..origin/main --oneline
git diff HEAD..origin/main
git merge --ff-only origin/main
pip install -e .
```

> **Review changes first:** Read the `git log` and `git diff` output before running `pip install -e .`, because reinstalling runs the newly pulled code on your machine.

If you are not installing from a local checkout, pin a specific commit or tag rather than an unpinned branch URL (an unpinned install fetches whatever is currently on the default branch):

```bash
pip install --upgrade --force-reinstall "git+https://github.com/bhsatan/Sescan.git@<commit-or-tag>"
```

---

## What SecScan Reads

Before any real scan runs, SecScan prints a permission notice listing what will be inspected and waits for confirmation. You can also run `secscan scan --dry-run` to see the exact commands and paths for your OS without collecting any data.

| Area | Windows (read-only) | Linux (read-only) | Needs Admin/Root? |
|---|---|---|---|
| **Firewall** | `Get-NetFirewallProfile` (PowerShell) | `systemctl is-active firewalld`, `/etc/ufw/ufw.conf` | No |
| **Disk Encryption** | `Get-BitLockerVolume` (PowerShell) | `lsblk -o NAME,TYPE,FSTYPE --json`, `/etc/crypttab` | Windows: Yes; Linux: No |
| **Antivirus** | `Get-MpComputerStatus` (PowerShell) | — | No |
| **Listening Ports** | `Get-NetTCPConnection -State Listen` (PowerShell) | `ss -tlnp` | No (process names on Linux may need root) |
| **User Accounts & Admins** | `Get-LocalUser -Name Guest`, `Get-LocalGroupMember -Group 'Administrators'` | `/etc/passwd`, `/etc/group` (`sudo`/`wheel`/`admin`) | No |
| **Password & Lockout Policy** | `net accounts` | `/etc/pam.d/common-password`, `/etc/pam.d/system-auth`, `/etc/pam.d/common-auth`, `/etc/security/pwquality.conf` (and `.d/`), `/etc/security/faillock.conf` | No |
| **SSH Server** | — | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*.conf`, `systemctl is-active sshd`/`ssh` | No (unless `sshd_config` is restricted) |
| **Remote Access (RDP / SMBv1)** | Registry `HKLM:\...\Terminal Server\fDenyTSConnections`, `...\RDP-Tcp\UserAuthentication`, `Get-SmbServerConfiguration` | — | SMBv1: Yes; RDP: No |
| **Automatic Login** | Registry `HKLM:\...\Winlogon\AutoAdminLogon` | `/etc/gdm3/custom.conf`, `/etc/gdm/custom.conf`, `/etc/lightdm/lightdm.conf`, `/etc/sddm.conf` | No |

---

## What SecScan Never Sends Anywhere

- **Core scan (`secscan scan`)**: Makes **zero** network connections. All fact collection, rule evaluation, scoring, and terminal/JSON/HTML report generation happen 100% locally on your machine.
- **Generated reports**: HTML reports embed all CSS and SVG inline—no CDNs, fonts, or external scripts are loaded.
- **Optional AI Explainer (`--ai-explain`)**:
  - **Disabled by default.** Only activates if you explicitly pass `--ai-explain` and set `SECSCAN_AI_API_KEY` in your environment.
  - **Interface-only in v0.1**: No LLM provider backend is implemented yet, so even with `--ai-explain`, **nothing is sent over the network in v0.1**.
  - **Redaction + Confirmation**: When a provider is wired up in a future release, `Redactor` strips MAC addresses, IPv4/IPv6 addresses, Windows/UNC/POSIX file paths, `DOMAIN\user` accounts, hostnames, and usernames first, then shows you the exact redacted payload and requires your `[y/N]` confirmation before any call is made.

---

## How the Score Is Computed

Each rule applicable to your OS has a severity weight:

| Severity | Weight |
|---|---|
| Critical | 10 |
| High | 7 |
| Medium | 4 |
| Low | 2 |

For each applicable rule:
- **`pass`** → earns full weight
- **`unknown`** (could not verify, e.g. needs admin) → earns half weight (`weight // 2`, integer division)
- **`fail`** → earns `0`

$$\text{score} = \mathrm{round}\!\left(100 \times \frac{\text{total earned}}{\text{total possible}}\right)$$

### Grade Bands

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 50–74 | C |
| 25–49 | D |
| 0–24 | F |

### Finding Ranking Order

Findings are sorted so the most urgent, easiest-to-fix problems appear first:
1. **Status**: `fail` → `unknown` → `pass`
2. **Severity**: `critical` → `high` → `medium` → `low`
3. **Difficulty**: `easy` → `medium` → `hard`

---

## Known Limitations (v0.1)

- **Windows & Linux only**: macOS, cloud accounts, and containers are out of scope in v0.1.
- **No live monitoring or auto-remediation**: SecScan runs on demand and only outputs text instructions.
- **Elevation limits**: Without administrator rights on Windows, BitLocker (`DISK-001`) and SMBv1 (`SMB-001`) report `unknown`.
- **Windows third-party antivirus**: `AV-001` checks Windows Defender via `Get-MpComputerStatus`; third-party AV products are not queried in v0.1.
- **Linux variations**:
  - Firewall checks `ufw` and `firewalld`; custom `nftables`/`iptables` setups without those services report `false` (`fail`).
  - `sshd_config` parser follows `Include` lines, but does not evaluate conditional `Match` blocks. It reports `unknown` if the main config cannot be read.
  - Password policy reports `unknown` if PAM files are unreadable; otherwise it applies the PAM module defaults.
  - Disk encryption passes if any LUKS volume exists, even if it is not the OS drive.
- **Skipped in v0.1**: OS patch currency (requires network/patch DB), screen-lock timeout (fragmented across Linux DEs), and backup presence (high false-negative risk).

---

## How to Add a Rule

Each rule is a single YAML file in `secscan/rules/` with no executable code. See [docs/ADDING_RULES.md](docs/ADDING_RULES.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for the full schema, supported operators (`equals`, `not_equals`, `greater_than`, `less_than`, `is_true`, `is_false`, `contains`, `not_contains`), collector guidelines, and test requirements.

---

## Short Threat Model

SecScan inspects sensitive local configuration—treat its output as confidential.

- **Assets**: Scan reports (JSON/HTML/terminal) reveal open ports, admin accounts, encryption status, and missing controls. Do not share reports publicly; HTML and terminal reports include a warning banner.
- **Trust boundaries**: SecScan trusts the local Python runtime and OS utilities it invokes (`subprocess.run` with argument lists, never `shell=True`). CLI `--output` paths are resolved via `Path.resolve()`.
- **External surface**: Zero outbound network calls in the core engine. The optional AI explainer is off by default, reads API keys from `SECSCAN_AI_API_KEY` only, redacts PII before preview, and requires explicit confirmation.

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model and vulnerability reporting process.

---

## Development

```bash
pip install -e ".[dev]"
pytest -v
ruff check .
ruff format --check .
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
