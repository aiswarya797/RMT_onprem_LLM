import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [artifactRoot, output, ...names] = process.argv.slice(2);
if (!artifactRoot || !output || names.length === 0) {
  throw new Error("usage: write-release-manifest.mjs ARTIFACT_ROOT OUTPUT ARTIFACT...");
}

const artifacts = names.map((name) => {
  const file = path.join(artifactRoot, name);
  return {
    name,
    size_bytes: fs.statSync(file).size,
    sha256: crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    trust: name.endsWith(".pkg")
      ? { developer_id_signed: process.env.RMT_BUILD_MODE === "release", notarized: process.env.RMT_BUILD_MODE === "release", stapled_ticket: process.env.RMT_BUILD_MODE === "release" }
      : { contained_binaries: process.env.RMT_BINARY_TRUST, archive_notarization: "not_staplable", integrity: process.env.RMT_BUILD_MODE === "release" ? "signed-checksum-manifest" : "unsigned-checksum-manifest" },
  };
});

const manifest = {
  schema_version: "1.0",
  product: "LLM Monitor",
  version: process.env.RMT_VERSION,
  build_id: process.env.RMT_BUILD_ID,
  mode: process.env.RMT_BUILD_MODE,
  qualified_release: process.env.RMT_BUILD_MODE === "release",
  binary_trust: process.env.RMT_BINARY_TRUST,
  package_trust: process.env.RMT_PACKAGE_TRUST,
  notarization: process.env.RMT_NOTARIZATION,
  notarization_submission_id: process.env.RMT_NOTARY_SUBMISSION_ID || null,
  developer_id_application: process.env.RMT_APPLICATION_IDENTITY || null,
  developer_id_installer: process.env.RMT_INSTALLER_IDENTITY || null,
  checksum_signature: process.env.RMT_CHECKSUM_SIGNATURE,
  trust_note: process.env.RMT_BUILD_MODE === "release"
    ? "The installer package is Developer ID signed, notarized and stapled. The tar archive cannot carry a stapled ticket; it contains the same Developer ID signed binaries and is bound by the detached signature over its checksum manifest."
    : "Development artifacts are not qualified releases.",
  artifacts,
};

fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });
