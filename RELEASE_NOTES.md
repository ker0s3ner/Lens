# Lens 0.6.8 — Fourier

## What's new

- Mach-O `LC_DATA_IN_CODE` ranges are excluded from executable discovery.
- Analysis notes record the number of embedded-data ranges recognized in Mach-O files.
- Decompiler types now survive call-result copy chains and explicit casts when the source type is unambiguous.
- Repeated assignments with conflicting or unknown types remain conservatively untyped.
- Release notes remain synchronized across Lens, GitHub Releases, and the public version history.

## Release cadence

Lens versions use `x.y.z`: major theme releases, monthly minor feature releases, and patch releases for fixes and quality-of-life improvements. The first full release, `1.0.0`, will be codenamed **Stokes**.
