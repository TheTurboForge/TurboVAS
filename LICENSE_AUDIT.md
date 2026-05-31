# License Audit

This is the initial TurboVAS engineering license and provenance audit for the imported upstream source snapshots. It is not legal advice.

The import preserves upstream component boundaries under `components/`. Upstream license files, copyright notices, package manifests, documentation, tests, and source files are retained as imported source material.

## Component License Summary

| Component | Path | License declaration observed | Preserved license/provenance files | Notes |
| --- | --- | --- | --- | --- |
| OpenVAS Scanner | `components/openvas-scanner` | Main non-Rust module is GPL-2.0 only overall, with per-file GPL-2.0 and GPL-2.0-or-later details. Rust implementation is GPL-2.0-or-later with OpenSSL exception; some files are additionally MIT. | `COPYING`, `rust/COPYING`, `license-details.md`, `RELICENSE/` | Highest-complexity component. Do not rewrite or normalize headers. Preserve per-file license detail and relicensing material. |
| gvm-libs | `components/gvm-libs` | GPL-2.0-or-later. | `COPYING` | Shared library dependency for multiple services. |
| gvmd | `components/gvmd` | AGPL-3.0-or-later. | `COPYING` | Network/server component. AGPL obligations matter for deployment and public access scenarios. |
| gsad | `components/gsad` | AGPL-3.0-or-later. | `LICENSE` | HTTP daemon. AGPL obligations matter for deployment and public access scenarios. |
| gsa | `components/gsa` | AGPL-3.0-or-later. | `LICENSE`, `package.json` license declaration | Web UI served over a network. AGPL obligations matter for deployment and public access scenarios. |
| ospd-openvas | `components/ospd-openvas` | AGPL-3.0-or-later. | `COPYING` | Includes its own `ospd` package. Preserve service/config documentation. |
| notus-scanner | `components/notus-scanner` | AGPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Scanner service with feed and MQTT integration implications. |
| openvas-smb | `components/openvas-smb` | GPL-2.0-or-later. | `COPYING` | README notes Samba-derived/forked GPLv2 basis. Requires deeper provenance review before public release or distribution. |
| greenbone-feed-sync | `components/greenbone-feed-sync` | GPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Source license does not determine Greenbone Community Feed data terms. Treat feed data/signature/use terms separately. |
| python-gvm | `components/python-gvm` | GPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Protocol library for GMP and OSP. |
| gvm-tools | `components/gvm-tools` | GPL-3.0-or-later. | `LICENSE`, `pyproject.toml` license declaration | Depends on `python-gvm`; useful for CLI/operator tooling and smoke tests. |

## Standing License Rules

- Preserve upstream license files and copyright notices.
- Do not rewrite, remove, or normalize license headers during routine changes.
- Record source provenance for every imported component, vendored dependency, generated source addition, or substantial source replacement.
- Update this file whenever source scope, component provenance, dependency scope, packaging, distribution, or release behavior changes.
- Treat feed content terms separately from source code licensing.
- Mark ambiguous cases for human/legal review before public release or distribution.

## Review Items

- Confirm whether TurboVAS should preserve upstream git history in a later archival/import refinement, or whether explicit source snapshots plus `UPSTREAMS.md` are sufficient.
- Review `components/openvas-scanner/license-details.md` before changing scanner/NASL/Rust license-sensitive files.
- Review `components/openvas-smb` Samba-derived provenance before public release or distribution.
- Review Greenbone Community Feed terms before bundling, redistributing, mirroring, or packaging feed content.
- Define release-time source publication and attribution procedures before making this repository public.
