# Stato — Client Portal

Static-hosted documents for the leadgeneration.io / WinTrading client.
Published via GitHub Pages.

## Live URL

After enabling GitHub Pages on this repository:

```
https://<your-github-username-or-org>.github.io/stato-client-portal/
```

## Files

| File | Purpose |
|---|---|
| `index.html` | Landing page — links to the form and the PDF |
| `2026-04-23-sam-information-request.html` | Interactive form Sam fills in (auto-saves, submits by email) |
| `2026-04-23-stato-status-report.pdf` | Detailed project status report |

## Update flow

```bash
# After editing any file:
git add .
git commit -m "docs: update for ..."
git push
```

GitHub Pages rebuilds automatically (~30 seconds).

## Adding a new status report

Just drop the new files (`.html` and/or `.pdf`) in the root and update
`index.html` to link to them.
