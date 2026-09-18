import fs from "node:fs";
import path from "node:path";

const [webRoot, goModulesFile, output] = process.argv.slice(2);
if (!webRoot || !goModulesFile || !output) {
  throw new Error("usage: write-sbom.mjs WEB_ROOT GO_MODULES_FILE OUTPUT");
}

const id = (value) => `SPDXRef-${value.replace(/[^A-Za-z0-9.-]/g, "-")}`;
const rootID = "SPDXRef-LLM-Monitor";
const packages = [{
  name: "LLM Monitor",
  SPDXID: rootID,
  versionInfo: process.env.RMT_VERSION,
  downloadLocation: "NOASSERTION",
  filesAnalyzed: false,
  licenseConcluded: "NOASSERTION",
  licenseDeclared: "NOASSERTION",
  copyrightText: "NOASSERTION",
}];
const relationships = [{ spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: rootID }];
let sqliteGoModuleID;

for (const line of fs.readFileSync(goModulesFile, "utf8").trim().split("\n")) {
  const [name, version] = line.split("|");
  if (!version) continue;
  const SPDXID = id(`Go-${name}-${version}`);
  const license = {
	"filippo.io/age": "BSD-3-Clause",
	"filippo.io/hpke": "BSD-3-Clause",
    "github.com/mattn/go-sqlite3": "MIT",
    "github.com/fxamacker/cbor/v2": "MIT",
    "github.com/x448/float16": "MIT",
    "github.com/klauspost/compress": "BSD-3-Clause AND Apache-2.0 AND MIT",
    "golang.org/x/crypto": "BSD-3-Clause",
    "golang.org/x/sys": "BSD-3-Clause",
  }[name] ?? "NOASSERTION";
  packages.push({ name, SPDXID, versionInfo: version, downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: "NOASSERTION", licenseDeclared: license, copyrightText: "NOASSERTION", externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: `pkg:golang/${name}@${version}` }] });
  relationships.push({ spdxElementId: rootID, relationshipType: "DEPENDS_ON", relatedSpdxElement: SPDXID });
  if (name === "github.com/mattn/go-sqlite3") sqliteGoModuleID = SPDXID;
}

const sqliteID = "SPDXRef-Native-SQLite-3.53.4";
packages.push({
  name: "SQLite",
  SPDXID: sqliteID,
  versionInfo: "3.53.4",
  supplier: "Organization: SQLite",
  downloadLocation: "NOASSERTION",
  filesAnalyzed: false,
  licenseConcluded: "NOASSERTION",
  licenseDeclared: "LicenseRef-SQLite-Public-Domain",
  copyrightText: "Public domain",
  comment: "Bundled SQLite amalgamation from github.com/mattn/go-sqlite3 v1.14.52; source ID 2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc.",
  externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:generic/sqlite@3.53.4" }],
});
relationships.push({ spdxElementId: sqliteGoModuleID ?? rootID, relationshipType: "CONTAINS", relatedSpdxElement: sqliteID });

const lock = JSON.parse(fs.readFileSync(path.join(webRoot, "package-lock.json"), "utf8"));
for (const [packagePath, metadata] of Object.entries(lock.packages ?? {})) {
  if (!packagePath || metadata.dev || !metadata.version) continue;
  const name = metadata.name ?? packagePath.slice(packagePath.lastIndexOf("node_modules/") + "node_modules/".length);
  const SPDXID = id(`NPM-${name}-${metadata.version}`);
  packages.push({ name, SPDXID, versionInfo: metadata.version, downloadLocation: metadata.resolved ?? "NOASSERTION", filesAnalyzed: false, licenseConcluded: "NOASSERTION", licenseDeclared: metadata.license ?? "NOASSERTION", copyrightText: "NOASSERTION", externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: `pkg:npm/${name}@${metadata.version}` }] });
  relationships.push({ spdxElementId: rootID, relationshipType: "DEPENDS_ON", relatedSpdxElement: SPDXID });
}

const document = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: `LLM-Monitor-${process.env.RMT_VERSION}`,
  documentNamespace: `https://llm-monitor.local/sbom/${encodeURIComponent(process.env.RMT_BUILD_ID)}`,
  creationInfo: { created: new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString(), creators: ["Tool: LLM Monitor packaging/scripts/write-sbom.mjs"] },
  hasExtractedLicensingInfos: [{ licenseId: "LicenseRef-SQLite-Public-Domain", extractedText: "SQLite deliverable code and documentation are dedicated to the public domain. See https://www.sqlite.org/copyright.html." }],
  packages,
  relationships,
};

fs.writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o644 });
