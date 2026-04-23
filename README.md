# Stato — Client Portal

Static client-facing portal for the leadgeneration.io / WinTrading project,
hosted on GitHub Pages. Includes a password-gated form Sam fills in,
encrypted submission stored in this repo, and an admin view that decrypts.

## Live URLs

- **Landing** — `https://yashc-0101.github.io/stato-client-portal/`
- **Form** (Sam) — `https://yashc-0101.github.io/stato-client-portal/2026-04-23-sam-information-request.html`
- **Admin view** (Yash) — `https://yashc-0101.github.io/stato-client-portal/view.html`
- **Status PDF** — `https://yashc-0101.github.io/stato-client-portal/2026-04-23-stato-status-report.pdf`

All three pages are protected by the same password (set in `lib.js` →
`CONFIG.passwordHash`). Default password is `stato2026`.

## How it works

1. Sam visits the form URL → password gate appears.
2. Sam types the access code Yash sent him → form unlocks.
3. Sam fills in answers → hits Submit.
4. JS encrypts the answers (AES-GCM via PBKDF2 from password) → PUTs
   `submissions.json` to this repo via the GitHub Contents API.
5. Yash visits the view URL → enters the same code → fetches and
   decrypts `submissions.json` → renders Sam's latest answers.

If Sam comes back to update, the form pre-loads his existing answers
(decrypted from `submissions.json`), he edits, re-submits, the file is
overwritten. View page always shows the latest.

## One-time setup

`lib.js` has a `CONFIG` object at the top with two values that need to be
set before going live:

1. **`CONFIG.token`** — a fine-grained GitHub Personal Access Token
   - Create at https://github.com/settings/personal-access-tokens/new
   - Repository access: only `stato-client-portal`
   - Permissions → Repository → Contents → Read and write
   - Paste into `CONFIG.token`
2. **`CONFIG.passwordHash`** — SHA-256 hex of the access password
   - Default is the hash of `stato2026`. Change to anything you want.
   - To compute a new hash:
     ```bash
     printf "%s" "your-new-password" | shasum -a 256
     ```

Then push to git — GitHub Pages rebuilds in ~30 seconds.

## Security model

| Risk | Mitigation |
|---|---|
| GitHub PAT is visible in `lib.js` source | Token is fine-grained: write to *one file* in *one repo*. Worst case: vandalism, easy to revert + rotate. |
| `submissions.json` is publicly readable | Contents are AES-GCM encrypted with a key derived from the password. Anyone fetching it sees gibberish. |
| Brute-forcing the password | PBKDF2 with 200,000 iterations slows guesses dramatically. Use a non-dictionary password to be safe. |
| Replay / vandalism via the leaked PAT | Possible but limited to overwriting `submissions.json`. Rotate the token if you suspect misuse. |

## Files

| File | Purpose |
|---|---|
| `index.html` | Landing page with three links |
| `2026-04-23-sam-information-request.html` | Sam's form (password-gated) |
| `view.html` | Admin view (password-gated) |
| `lib.js` | Shared crypto + GitHub Contents API + password gate |
| `2026-04-23-stato-status-report.pdf` | Detailed project status PDF |
| `submissions.json` | Auto-created on first submission (encrypted) |

## Update flow

```bash
cd stato-client-portal
git add . && git commit -m "docs: update for ..." && git push
```

GitHub Pages rebuilds in ~30 seconds. Same URLs.
