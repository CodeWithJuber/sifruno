# Sifruno visual direction

User direction: innovation, imagination and a real brand feel, with no fancy decoration.

Approved identity: original V3 Sifruno Display logo lettering. The user explicitly selected V3 on 2026-10-04. Use the same S, matching stems, circular counters and repeated angled endings. Sifr is teal, uno is ink; reverse with mint/white on dark. Inter stays the interface font. Initial Inter-derived directions remain archived. No gradients, glow, ornamental patterns or decorative animation.

Product surfaces use neutral white/slate palettes, thin borders and modest 8px corners, a compact sidebar and topbar, readable metrics and dense rows. The design system is shadcn/ui on Base UI with Tailwind 4, alone: the [product plan](docs/PRODUCT-PLAN.md) ("Design system ka faisla") ends the earlier mix of Astryx, shadcn and hand-written CSS. The panel shell (sidebar, top bar, search, page URLs) is already shadcn/ui; the Astryx screens inside it stay until each is rebuilt, and no new screen is built with Astryx. The original square editorial brand preview remains a separate asset browser. The earlier dashboard concept and its notes are in `docs/archive/dashboard-design.md`.

The brand guide in `docs/brand-guidelines.md` defines the identity. `assets/design-tokens.json` holds the exact values; `assets/design-tokens.css` exposes them to applications. In the source repository, logo and icon exports are reproducible with `npm run brand:build`. The downloadable ZIP contains ready-to-use assets, not the build toolchain.

Preview acceptance: all assets resolve locally; no horizontal overflow at 390px or 1440px; usable keyboard focus; light and dark logo variants; readable mark at 16px and 32px; at least 4.5:1 contrast for normal text. Preview interactions select a theme, copy colors and download real files. Branding does not claim that the hosting engine has achieved cPanel compatibility.
