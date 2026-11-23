# Reused UI sources and assets

- Official Meta Astryx React components and precompiled neutral theme 0.6.5: https://astryx.atmeta.com and https://github.com/facebook/astryx (MIT). The dashboard uses its Button, Card, SideNav, SegmentedControl, ProgressBar and Theme implementations. StyleX 0.19.1: https://github.com/facebook/stylex (MIT).
- Official shadcn UI component source, added with shadcn CLI 4.21.1 and the `base-nova` registry style: https://ui.shadcn.com and https://github.com/shadcn-ui/ui (MIT).
- Base UI React primitives: https://base-ui.com/react and https://github.com/mui/base-ui (MIT).
- TanStack Router 1.170.46 for page URLs: https://tanstack.com/router and https://github.com/TanStack/router (MIT). Its runtime dependency isbot is Unlicense.
- React: https://github.com/facebook/react (MIT).
- Tailwind CSS: https://github.com/tailwindlabs/tailwindcss (MIT).
- Lucide React interface icons: https://github.com/lucide-icons/lucide (ISC).
- Inter font: https://github.com/rsms/inter (SIL Open Font License). The shipped local font license is copied into `public/brand/licenses`.
- Vite: https://github.com/vitejs/vite (MIT). TypeScript: https://github.com/microsoft/TypeScript (Apache-2.0).

The Sifruno V3 logotype and S mark are original project assets. No third-party corporate mark is included. Retain library license files from their package distributions and the copied asset licenses when redistributing this application.

Pinned upstream MIT notices are retained in [licenses/astryx/LICENSE](licenses/astryx/LICENSE) for Astryx core and theme-neutral 0.6.5, and [licenses/stylex/LICENSE](licenses/stylex/LICENSE) for StyleX 0.19.1. These unmodified files come from the exact official release commits, with source URLs, SHA-256 hashes, package versions and npm integrity records in the adjacent `provenance.json` files. Astryx's source commit was also matched to the official npm SLSA provenance payloads; this record does not claim independent verification of attestation signatures. Preserve these notices and manifests in release archives when a published package omits its own LICENSE file.
