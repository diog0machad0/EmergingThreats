# Scriba — Cybersecurity Advisory PDF Generator

Scriba turns analyst-authored Markdown into professionally formatted PDF advisories using a
deterministic production pipeline:

`Markdown → parser → Jinja2 templates → HTML → WeasyPrint PDF`

## Features

- YAML frontmatter metadata (`tlp`, `date`, `author`, `classification`, `template`)
- Report title extracted from first body `# H1` (not metadata)
- Optional subtitle extracted from first `## H2`
- Optional `(IDENTIFIER)` parenthetical at the end of the title rendered as a coral italic
  sub-line on the cover (e.g. `(CVE-2026-32746)`)
- Cover page, running header/footer, and automatic `Page X of Y` numbering
- TLP classification banner (color-coded `WHITE` / `GREEN` / `AMBER` / `RED`)
- Styled tables, bullet/numbered lists, blockquotes, code blocks
- Custom fenced `ioc` blocks for IOC formatting
- Reusable templates and components

## Project Structure

```
scriba/
├── src/                # Build pipeline modules
├── templates/          # Base + advisory templates and components
│   └── components/
├── styles/             # main / cover / print CSS
├── assets/             # Logo, cover background, optional fonts
├── reports/            # Analyst Markdown reports
├── output/             # Generated PDFs (created on demand)
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Installation

WeasyPrint requires native system libraries (Pango, Cairo, GDK-PixBuf, GObject).
`pip install` only installs the Python bindings; you **must** install the OS-level
libraries first or PDF generation will fail with `cannot load library 'libgobject-2.0-0'`
(or similar).

### macOS

```bash
brew install pango cairo gdk-pixbuf libffi
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Linux (Debian / Ubuntu)

```bash
sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf2.0-0 libffi-dev
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows

WeasyPrint on Windows needs the **GTK runtime** (DLLs for GObject, Pango, Cairo, etc.).
Pick one of the two options:

**Option A — GTK3 Runtime installer (simplest):**

1. Download the latest `gtk3-runtime-*-ts-win64.exe` from
   https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
2. Run it and tick "Set up PATH environment variable to include GTK+" during install.
3. **Close and reopen PowerShell** so the new `PATH` is picked up.
4. Verify the DLLs are visible:
   ```powershell
   where libgobject-2.0-0.dll
   ```
5. Then create the venv and install:
   ```powershell
   py -3.12 -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

**Option B — MSYS2 (upstream-recommended):**

1. Install MSYS2 from https://www.msys2.org/
2. Open the *MSYS2 MINGW64* shell and run:
   ```bash
   pacman -S mingw-w64-x86_64-pango
   ```
3. Add `C:\msys64\mingw64\bin` to the system `PATH`.
4. Restart PowerShell, then run the venv steps from Option A.

### Verify WeasyPrint is importable

```bash
python -c "from weasyprint import HTML; print('weasyprint ok')"
```

If this prints `weasyprint ok`, you're ready to generate PDFs.

## Generate a PDF

```bash
python -m src.build reports/sample_advisory.md --template advisory --output output/report.pdf
```

If `--template` is omitted, the value from frontmatter `template` is used.

## How Analysts Write Reports

Analysts edit only Markdown files in `reports/`. Frontmatter is the **only** metadata block;
the title belongs in the body.

```markdown
---
tlp: WHITE
date: 2026-03-18
author: Security Joes
classification: Proprietary and Confidential
template: advisory
---

# Critical Telnetd Remote Code Execution Vulnerability (CVE-2026-32746)

## Security Advisory

# Executive Summary

A critical vulnerability has been identified...

# Details

...

| Product | Affected Version | Fixed Version |
| --- | --- | --- |
| GNU Inetutils telnetd | ≤ 2.5 | 2.6 and later |

# Recommendations

- Apply vendor patches.
- Disable Telnet services.
```

IOC blocks render with custom dark styling:

````markdown
```ioc
malicious-domain.com
1.2.3.4
ab13cc8d4329f5f1539f48d6ac6a53ce7adf0e4cb5d0994bb4fb0c2c8037262b
```
````

## Template System

- `templates/base.html.j2` — root HTML document.
- `templates/advisory.html.j2` — advisory layout (cover + content body).
- `templates/components/` — reusable components (cover, header, footer, tlp_banner, section).

To add a new template:

1. Create `templates/<name>.html.j2` (extend `base.html.j2`).
2. Reuse existing components or add new ones under `templates/components/`.
3. Set `template: <name>` in report frontmatter, or pass `--template <name>` on the CLI.

## Branding Assets

- `assets/cover-bg.png` — full-bleed hero image used at the top of the cover (≈210mm × 117.7mm
  on A4 at native aspect ratio).
- `assets/logo.png` — wordmark used in the running page header (top-left) and at the bottom of
  the cover.

Replace these two files to rebrand the system end-to-end.

## WeasyPrint Troubleshooting

- Verify import works:
  `python -c "from weasyprint import HTML; print('ok')"`
- "Fontconfig: No writable cache directories" warnings on macOS are harmless and do not block
  PDF generation.
- If image paths fail to render, remember:
  - HTML `<img src>` is resolved relative to the project root (the WeasyPrint `base_url`).
  - CSS `url()` is resolved relative to the CSS file location.
- If `weasyprint` install fails on macOS due to native libraries, install
  `pango cairo gdk-pixbuf libffi` via Homebrew before `pip install`.
