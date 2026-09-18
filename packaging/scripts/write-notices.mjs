import fs from "node:fs";
import path from "node:path";

const [webRoot, licenseRoot, output] = process.argv.slice(2);
if (!webRoot || !licenseRoot || !output) {
  throw new Error("usage: write-notices.mjs WEB_ROOT GO_LICENSE_ROOT OUTPUT");
}

const lock = JSON.parse(fs.readFileSync(path.join(webRoot, "package-lock.json"), "utf8"));
const sections = [
  "LLM Monitor third-party notices",
  "Generated from pinned production dependencies. Build and test tools are pinned in the lockfile and dependency record but are not shipped in the web bundle.",
];

for (const [packagePath, metadata] of Object.entries(lock.packages ?? {})) {
  if (!packagePath || metadata.dev || !metadata.version) continue;
  const packageName = metadata.name ?? packagePath.slice(packagePath.lastIndexOf("node_modules/") + "node_modules/".length);
  const moduleRoot = path.join(webRoot, packagePath);
  const licenseName = fs.readdirSync(moduleRoot).find((name) => /^licen[cs]e(?:\..*)?$/i.test(name));
  if (!licenseName) throw new Error(`missing license text for ${packageName}@${metadata.version}`);
  sections.push(
    `${"=".repeat(72)}\n${packageName} ${metadata.version} (${metadata.license ?? "license not declared"})\n\n${fs.readFileSync(path.join(moduleRoot, licenseName), "utf8").trim()}`,
  );
}

for (const name of ["filippo.io-age.txt", "filippo.io-hpke.txt", "github.com-mattn-go-sqlite3.txt", "github.com-fxamacker-cbor-v2.txt", "github.com-klauspost-compress.txt", "github.com-x448-float16.txt", "golang.org-x-crypto.txt", "golang.org-x-sys.txt", "sqlite.txt"]) {
  sections.push(`${"=".repeat(72)}\n${fs.readFileSync(path.join(licenseRoot, name), "utf8").trim()}`);
}

fs.writeFileSync(output, `${sections.join("\n\n")}\n`, { mode: 0o644 });
