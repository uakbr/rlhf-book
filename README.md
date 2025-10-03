# Microsoft Sentinel Whitepaper

This repository contains the source for *Modernizing Security Operations with Microsoft Sentinel*, an executive and technical whitepaper detailing how to deploy, operate, and govern Microsoft Sentinel. The content is authored in Markdown, compiled with Pandoc, and distributed as PDF, HTML, EPUB, and DOCX artifacts.

## Repository Structure

- `chapters/` — Section Markdown files for the whitepaper, numbered to control ordering.
- `images/` — Visual assets (architecture diagrams, workflow illustrations).
- `templates/` — Customized Pandoc templates aligned to Microsoft branding.
- `metadata.yml` — Global metadata (title, subtitle, authorship, abstract, licensing).
- `Makefile` — Build automation for PDF/HTML/EPUB/DOCX outputs.

## Building the Whitepaper

Prerequisites:

- [Pandoc 3.x](https://pandoc.org/installing.html)
- `pandoc-crossref`
- LaTeX engine (for PDF) such as `texlive-xetex`
- GNU Make

Build commands:

```sh
make            # builds epub, html, pdf, docx
make html       # HTML only
make pdf        # PDF only
make clean      # remove build artifacts
```

Artifacts are written to `build/<format>/` (e.g., `build/pdf/sentinel-whitepaper.pdf`).

## Content Contributions

Please follow these guidelines when contributing:

1. Update `todo.md` with a timestamped journal entry describing the change.
2. Maintain executive-first tone with technical detail available via appendices and callouts.
3. Cite authoritative Microsoft or industry sources using `chapters/bib.bib`.
4. Provide accessible imagery (alt text, readable color contrast) and ensure assets render in all outputs.

## Licensing

- **Content:** © 2025 Microsoft Corporation. All rights reserved.
- **Code & build tooling:** MIT License (see `LICENSE` where applicable).

For questions or publishing coordination, contact the Microsoft Security Solutions Team.
