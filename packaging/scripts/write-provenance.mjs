import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [projectRoot, binaryRoot, output] = process.argv.slice(2);
if (!projectRoot || !binaryRoot || !output) {
  throw new Error("usage: write-provenance.mjs PROJECT_ROOT BINARY_ROOT OUTPUT");
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function record(relativePath) {
  const file = path.join(projectRoot, relativePath);
  return { path: relativePath, sha256: sha256(file), size_bytes: fs.statSync(file).size };
}

const provenance = {
  schema_version: "1.0",
  product: "LLM Monitor",
  version: process.env.RMT_VERSION,
  build_id: process.env.RMT_BUILD_ID,
  mode: process.env.RMT_BUILD_MODE,
  source_date_epoch: Number(process.env.SOURCE_DATE_EPOCH),
  target: { os: "darwin", architecture: "arm64", minimum_macos: process.env.RMT_MIN_MACOS, cgo_enabled: true },
  tools: {
    go: process.env.RMT_GO_VERSION,
    node: process.env.RMT_NODE_VERSION,
    npm: process.env.RMT_NPM_VERSION,
    sdk: process.env.RMT_SDK_VERSION,
  },
  inputs: [record("go.mod"), record("go.sum"), record("web/package.json"), record("web/package-lock.json")],
  outputs: ["llm-monitor", "llm-monitor-collector"].map((name) => {
    const file = path.join(binaryRoot, name);
    return { name, sha256: sha256(file), size_bytes: fs.statSync(file).size, signature_mode: process.env.RMT_BINARY_TRUST };
  }),
  reproducibility: {
    source_and_dependency_inputs_pinned: true,
    compiler_path_required: true,
    package_bytes_reproducible: false,
    note: "SOURCE_DATE_EPOCH normalizes staged payload times. Apple package, signature, timestamp and notarization metadata can still vary between builds.",
  },
  trust: {
    release_qualified: false,
    signed: process.env.RMT_BUILD_MODE === "release",
    notarized: false,
    note: process.env.RMT_BUILD_MODE === "release"
      ? "Final release trust is recorded only after signature, notarization, stapling and Gatekeeper verification complete."
      : "Development binaries are ad-hoc signed and the installer package is unsigned. This is not a customer release.",
  },
};

fs.writeFileSync(output, `${JSON.stringify(provenance, null, 2)}\n`, { mode: 0o644 });
