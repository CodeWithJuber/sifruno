import { cp, mkdir, writeFile } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import path from "node:path"

const web = fileURLToPath(new URL("..", import.meta.url))
const source = path.resolve(web, "../assets/brand")
const target = path.join(web, "public/brand")
await mkdir(target, { recursive: true })
for (const dir of ["logos", "favicons", "fonts", "licenses"]) {
  await cp(path.join(source, dir), path.join(target, dir), { recursive: true })
}
await mkdir(path.join(target, "icons"), { recursive: true })
for (const file of ["sifruno-app-icon-192.png", "sifruno-app-icon-512.png", "sifruno-maskable-512.png"]) {
  await cp(path.join(source, "icons", file), path.join(target, "icons", file))
}
await writeFile(path.join(web, "public/site.webmanifest"), JSON.stringify({
  name: "Sifruno workbench", short_name: "Sifruno", start_url: "/", display: "standalone",
  background_color: "#F4F8F7", theme_color: "#142F35",
  icons: [
    { src: "/brand/icons/sifruno-app-icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
    { src: "/brand/icons/sifruno-app-icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
    { src: "/brand/icons/sifruno-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
  ],
}, null, 2) + "\n")
console.log("Approved Sifruno assets synced into web/public/brand")
