# Sifruno

Sifruno is the selected name for the hosting control panel. The user approved **V3 custom Sifruno Display lettering, with Sifr teal and uno ink**, on 2026-10-04. This is the official visual identity. On dark surfaces use mint and white. The tagline is **Zero friction. Full control.** The name is coined, inspired by *sifr*, meaning zero; it is not presented as an ancient word. This identity expresses clear control and practical invention. Branding is separate from product compatibility evidence.

## Logo

The official S mark is a continuous geometric shape with two angled terminals. The approved wordmark integrates that exact S as its first letter, followed by custom ifruno letterforms. Canonical `sifruno-logo-*` and `sifruno-wordmark-*` files export the approved V3 identity. SVG logo rendering does not depend on an installed font. Version 1 used Inter Semibold with a separate badge; its files now carry the `sifruno-v1-*` prefix as an archived concept.

**Version 2**, requested as an additional direction, integrates the exact same geometric S as the first letter of **Sifruno**. There is no extra S badge. The remaining letters are outlined Inter Bold to approach the mark's weight. `logos/sifruno-v2-sifr-uno-primary.svg` colors **Sifr** teal and **uno** ink; `sifruno-v2-sif-runo-primary.svg` uses **Sif** teal and **runo** ink. Both retain the exact seven-letter spelling, without a space. Dark and mono variants are included. The original mark, app icons and favicons work with either direction. `social/sifruno-v2-comparison.png` compares both with version 1. Version 2 and the alternate color split are archived concepts; use approved V3 Sifr/uno in product surfaces.

**Version 3** answers the request for more distinctive typography. **Sifruno Display** is original, custom logo lettering: seven vector glyphs with a shared 10-unit stem, circular counters, and repeated angled terminals. The exact S silhouette carries into the i dot and the f/r endings. All letters are drawn for this logotype; no Inter outlines are used in version 3. The letters u/n mirror their arch construction; the o has a circular counter. These small repeated details give the name its own visual rhythm without added decoration. The approved wordmark is `logos/sifruno-v3-sifr-uno-primary.svg`; dark, mono and alternative Sif/runo color grouping are included. Its construction is editable in `lettering/sifruno-display.json`. This is logo lettering, not a complete installable typeface: it does not contain the full alphabet, numbers or body-text shaping. The preview uses this approved direction; versions 1 and 2 remain in its archived-concepts section.

The study of [Google's identity design](https://design.google/library/evolving-google-identity), [Facebook's identity redesign](https://www.meta.com/design-at-meta/blog/redefining-facebooks-brand-identity/), [Amazon's official logo gallery](https://press.aboutamazon.com/logos) and [AWS's brand resources](https://aws.amazon.com/co-marketing/) informed the approach. Our design interpretation is to give the name a distinctive repeated geometry, use a compact initial for small surfaces, keep a restrained palette and maintain consistent spacing. No third-party brand logo or typeface is included in Sifruno's custom lettering.

Use `assets/brand/logos/sifruno-logo-primary.svg` on paper or white. Use `sifruno-logo-on-dark.svg` on deep ink. Mono variants are supplied for one-color printing and restricted UI contexts. Use the isolated S mark for favicons, app launchers and avatars. Use the complete logo in the panel header and public materials.

Leave at least one stem width around the logo (10 units for a 64-unit mark). Minimum full-logo width is 120px. Minimum standalone mark is 16px; below 24px, prefer the supplied favicon over a full wordmark. Keep the provided aspect ratio and colors. Avoid extra outlines, shadows, gradients, rotations, enclosing shapes and rewritten lettering. Backgrounds must preserve the shape's contrast.

## Color

| Token | Value | Use |
| --- | --- | --- |
| Ink | `#142F35` | Main text, dark surfaces and app-icon ground |
| Teal | `#087F6F` | Brand mark and purposeful emphasis on light surfaces |
| Mint | `#B9E5D5` | Brand mark and emphasis on dark surfaces |
| Paper | `#F4F8F7` | Default canvas |
| White | `#FFFFFF` | Raised light surfaces and reversed text |
| Muted | `#52666B` | Secondary text on light surfaces |

`assets/design-tokens.json` is the exact, machine-readable palette. In the source repository, regenerate CSS and exports with `npm run brand:build` after editing it, then update this table and the preview labels. The ready-to-use ZIP does not include build dependencies or scripts. Use teal on light backgrounds and mint on dark backgrounds; teal body text on ink is unsuitable. Colors do not replace textual status labels.

## Typography and interface icons

Use Inter Regular for body copy, Medium for controls, and Semibold for titles. Default body size is 16px with 1.6 line height. Use system sans-serif fallbacks. The preview includes local Latin WOFF2 files and the Inter SIL Open Font License. When multilingual UI ships, add the corresponding scripts/fonts; these Latin assets alone do not provide Arabic or Hebrew typography. [Inter source and licensing](https://github.com/rsms/inter).

Use the reused Lucide family for interface actions, on a 24px grid with its standard 2px stroke. Twelve exported icons cover dashboard, domains, servers, databases, mail, backups, security, plugins, workflows, terminal, settings and users. They are interface symbols, separate from the original Sifruno logo. Keep labels for ambiguous actions. [Lucide source and license](https://github.com/lucide-icons/lucide).

## Voice

Calm, direct and helpful. Describe the action and its result. Prefer “Restore backup” to “Unleash recovery.” Explain errors with the affected item and next useful action. Avoid exaggerated AI claims and compatibility promises that have not passed the acceptance suite.

## Files and integration

`assets/brand/index.html` is the local responsive preview. Its download links point to actual assets. `asset-manifest.json` records SHA-256 and size for generated files. SVGs are editable vectors. PNGs are ready to use. ICO contains 16px, 32px and 48px PNG frames. App icons include 192px, 512px, 1024px and a maskable 512px version; Apple touch icon is 180px. The social avatar is 1024px and cover is 1200 × 630px.

Copy the entire `assets/brand` directory to your app's public `/brand/` directory, then put this in the HTML head:

```html
<link rel="icon" href="/brand/favicons/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/brand/favicons/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="/brand/favicons/apple-touch-icon.png">
<link rel="manifest" href="/brand/site.webmanifest">
<meta name="theme-color" content="#142F35">
```

The manifest assumes the app is mounted at `/brand/`; change `start_url` to your real app entry when integrating. These assets do not register a domain, reserve social handles or establish trademark clearance. Retain the included licenses when redistributing the fonts and Lucide icons.
