#!/usr/bin/env node
/**
 * Finite real-browser U02 smoke.
 *
 * Uses one owned packaged hub and one fresh headless Chrome profile. It never
 * installs a package, loads a LaunchAgent, contacts Ollama, or reuses an
 * existing browser profile. Results are behavioral smoke evidence, not manual
 * accessibility or clean-host release qualification.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT = fileURLToPath(import.meta.url);
const PROJECT = path.resolve(path.dirname(SCRIPT), "../..");
const PLAYWRIGHT = process.env.PLAYWRIGHT_MODULE;
if (!PLAYWRIGHT) throw new Error("Set PLAYWRIGHT_MODULE to an installed playwright/index.mjs");
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const DEFAULT_BINARY = path.join(PROJECT, ".work/packaging/development-0.1.0.9Qsxqb/payload/Library/Application Support/LLM Monitor/bin/llm-monitor");
const OUTER_DEADLINE_MS = 180_000;
const INSTALLED_CLI = '"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor"';

process.umask(0o077);

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function writePrivateJSON(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function parseOption(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

class PreflightError extends Error {
  constructor(step, cause) {
    super("browser preflight failed");
    this.name = "PreflightError";
    this.step = step;
    this.osErrorCode = typeof cause?.code === "string" ? cause.code : undefined;
    this.cliExitCode = Number.isInteger(cause?.cliExitCode) ? cause.cliExitCode : undefined;
    this.cliSafeCode = typeof cause?.cliSafeCode === "string" ? cause.cliSafeCode : undefined;
    this.cliMessage = typeof cause?.cliMessage === "string" ? cause.cliMessage.slice(0, 256) : undefined;
  }
}

async function outer() {
  const runID = crypto.randomBytes(6).toString("hex");
  const runRoot = path.join(PROJECT, ".work/u02-browser-smoke", runID);
  const temp = path.join(runRoot, "tmp");
  fs.mkdirSync(temp, { recursive: true, mode: 0o700 });
  const binary = path.resolve(parseOption("--binary", DEFAULT_BINARY));
  const collectorOption = parseOption("--collector-binary", "");
  const child = spawn(process.execPath, [SCRIPT, "--worker", "--run-id", runID, "--binary", binary,
    ...(collectorOption ? ["--collector-binary", collectorOption] : []),
    ...(process.argv.includes("--bounded-browser") ? ["--bounded-browser"] : [])], {
    detached: true,
    stdio: "inherit",
    env: { ...process.env, TMPDIR: temp },
  });

  let finished = false;
  const exitCode = await new Promise((resolve) => {
    child.once("exit", (code, signal) => {
      if (finished) return;
      finished = true;
      resolve(code ?? (signal ? 1 : 0));
    });
    child.once("error", () => {
      if (finished) return;
      finished = true;
      resolve(1);
    });
    setTimeout(async () => {
      if (finished) return;
      try { process.kill(-child.pid, "SIGTERM"); } catch {}
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 2_000));
      try { process.kill(-child.pid, "SIGKILL"); } catch {}
      const resultFile = path.join(runRoot, "result.json");
      if (!fs.existsSync(resultFile)) {
        writePrivateJSON(resultFile, {
          schema_version: "1.0",
          test: "u02_real_browser",
          run_id: runID,
          status: "fail",
          failure_step: "outer_deadline",
          failure_type: "TimeoutError",
          outer_deadline_ms: OUTER_DEADLINE_MS,
          script_sha256: sha256(SCRIPT),
        });
      }
      if (!finished) {
        finished = true;
        resolve(124);
      }
    }, OUTER_DEADLINE_MS).unref();
  });
  process.exitCode = exitCode;
}

async function reserveLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  if (!port) throw new Error("port reservation failed");
  return port;
}

function runCLI(command, args, env) {
  const result = spawnSync(command, args, { env, encoding: "utf8", timeout: 15_000, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) {
    let body = {};
    try { body = JSON.parse(result.stdout); } catch {}
    const error = new Error("CLI command failed");
    error.code = result.error?.code;
    error.cliExitCode = result.status;
    error.cliSafeCode = body.code;
    error.cliMessage = body.message;
    throw error;
  }
  return JSON.parse(result.stdout);
}

async function waitForHub(origin, child) {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("hub exited during startup");
    try {
      const response = await fetch(`${origin}/api/v1/auth/bootstrap`, { signal: AbortSignal.timeout(500) });
      if (response.status === 200) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("hub startup deadline exceeded");
}

async function stopOwnedChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(() => resolve(false), 5_000)),
  ]);
  if (exited === false && child.exitCode === null) {
    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("exit", resolve));
  }
}

function walkFiles(root) {
  const files = [];
  if (!fs.existsSync(root)) return files;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(candidate));
    else if (entry.isFile()) files.push(candidate);
  }
  return files;
}

function assertCanariesAbsent(root, canaries) {
  const needles = canaries.map((value) => Buffer.from(value));
  for (const file of walkFiles(root)) {
    const stat = fs.statSync(file);
    if (stat.size > 64 * 1024 * 1024) continue;
    const content = fs.readFileSync(file);
    if (needles.some((needle) => content.includes(needle))) throw new Error("authentication canary persisted");
  }
}

function pathnameOnly(value) {
  try { return new URL(value).pathname; } catch { return null; }
}

async function worker() {
  const started = Date.now();
  const runID = parseOption("--run-id", "");
  const binary = path.resolve(parseOption("--binary", DEFAULT_BINARY));
  const collectorOption = parseOption("--collector-binary", "");
  const collectorBinary = collectorOption ? path.resolve(collectorOption) : null;
  if (!/^[0-9a-f]{12}$/.test(runID)) throw new Error("invalid run id");
  if (!binary.startsWith(`${PROJECT}${path.sep}`) || !fs.statSync(binary).isFile()) throw new Error("binary must be a project-local file");
  if (collectorBinary && (!collectorBinary.startsWith(`${PROJECT}${path.sep}`) || !fs.statSync(collectorBinary).isFile())) throw new Error("collector must be project-local");
  if (!fs.statSync(PLAYWRIGHT).isFile() || !fs.statSync(CHROME).isFile()) throw new Error("pinned browser runtime is missing");

  const runRoot = path.join(PROJECT, ".work/u02-browser-smoke", runID);
  const home = path.join(runRoot, "Install home with spaces");
  const profile = path.join(runRoot, "chrome-profile");
  const runtime = path.join(PROJECT, ".work", `b-${runID.slice(0, 8)}`);
  const guard = path.join(runRoot, "guard");
  const launchLog = path.join(runRoot, "unexpected-launchctl.log");
  const hubLogPath = path.join(runRoot, "hub.log");
  const screenshot = path.join(runRoot, "no-target.png");
  const resultFile = path.join(runRoot, "result.json");
  for (const directory of [runRoot, home, profile, runtime, guard]) fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (["hub.sock", "collector.sock"].some((name) => Buffer.byteLength(path.join(runtime, name)) >= 104)) throw new Error("runtime socket path is too long");

  fs.writeFileSync(path.join(guard, "launchctl"), '#!/bin/sh\numask 077\nprintf "%s\\n" "$*" >> "$RMT_TEST_LAUNCHCTL_LOG"\nexit 97\n', { mode: 0o700 });
  const env = {
    ...process.env,
    TMPDIR: path.join(runRoot, "tmp"),
    PATH: `${guard}${path.delimiter}${process.env.PATH ?? ""}`,
    RMT_TEST_LAUNCHCTL_LOG: launchLog,
  };
  fs.mkdirSync(env.TMPDIR, { recursive: true, mode: 0o700 });

  let version;
  let port;
  let common;
  let tokenFile;
  try {
    version = runCLI(binary, ["version", "--json"], env);
  } catch (error) {
    throw new PreflightError("version", error);
  }
  try {
    port = await reserveLoopbackPort();
  } catch (error) {
    throw new PreflightError("reserve_loopback_port", error);
  }
  const origin = `http://127.0.0.1:${port}`;
  common = ["--installation-root", home, "--runtime-dir", runtime, "--listen", `127.0.0.1:${port}`];
  let setup;
  try {
    setup = runCLI(binary, [...common, "setup", "local", "--no-start", "--json"], env);
  } catch (error) {
    throw new PreflightError("setup", error);
  }
  try {
    tokenFile = path.resolve(setup.bootstrap_token_path);
    if (!tokenFile.startsWith(`${home}${path.sep}`) || (fs.statSync(tokenFile).mode & 0o777) !== 0o600) throw new Error("bootstrap token boundary failed");
  } catch (error) {
    throw new PreflightError("token_boundary", error);
  }
  const bootstrapToken = fs.readFileSync(tokenFile, "utf8").trim();
  const username = "browser-smoke-admin";
  const password = `P-${crypto.randomBytes(24).toString("base64url")}`;
  const mismatch = `M-${crypto.randomBytes(24).toString("base64url")}`;

  const passed = [];
  let step = "start_hub";
  let hub;
  let collector;
  let collectorLog;
  let hubLog;
  let context;
  const pageErrors = [];
  const consoleErrors = [];
  const localNon2xx = [];
  const remoteRequests = [];
  let bootstrapPosts = 0;
  const report = {
    schema_version: "1.0",
    test: "u02_real_browser",
    run_id: runID,
    status: "fail",
    outer_deadline_ms: OUTER_DEADLINE_MS,
    browser: "Google Chrome headless with fresh project-local profile",
    playwright_version: JSON.parse(fs.readFileSync(path.join(path.dirname(PLAYWRIGHT), "package.json"), "utf8")).version,
    binary_sha256: sha256(binary),
    binary_identity: version,
    script_sha256: sha256(SCRIPT),
    state_directory: runRoot,
    runtime_directory: runtime,
    screenshot,
    launchd: "guarded; no installation or service load permitted",
    accessibility_scope: "automated labels, keyboard focus, and alert semantics only; no manual accessibility claim",
  };

  const check = (condition, description) => {
    if (!condition) throw new Error("browser assertion failed");
    passed.push(description);
  };

  try {
    hubLog = fs.openSync(hubLogPath, "a", 0o600);
    hub = spawn(binary, [...common, "hub", "serve"], { env, stdio: ["ignore", hubLog, hubLog] });
    await waitForHub(origin, hub);

    step = "launch_browser";
    const { chromium } = await import(pathToFileURL(PLAYWRIGHT).href);
    context = await chromium.launchPersistentContext(profile, {
      executablePath: CHROME,
      headless: true,
      viewport: process.argv.includes("--bounded-browser") ? { width: 1100, height: 800 } : { width: 1440, height: 1000 },
      locale: "en-US",
      colorScheme: "light",
      args: [
        ...(process.argv.includes("--bounded-browser") ? ["--single-process", "--disable-gpu", "--no-zygote", "--js-flags=--max-old-space-size=32"] : []),
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-notifications",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-first-run",
        "--password-store=basic",
        "--use-mock-keychain",
        "--disable-features=AutofillServerCommunication,OptimizationHints,PasswordManagerOnboarding",
      ],
    });
    context.setDefaultTimeout(10_000);
    context.setDefaultNavigationTimeout(15_000);
    const page = context.pages()[0] ?? await context.newPage();
    page.on("pageerror", () => pageErrors.push("pageerror"));
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      const statusMatch = message.text().match(/status of (\d{3})/);
      consoleErrors.push({
        category: message.text().startsWith("Failed to load resource") ? "resource-load" : "console-error",
        pathname: pathnameOnly(message.location().url),
        status: statusMatch ? Number(statusMatch[1]) : null,
      });
    });
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (url.origin === origin && response.status() >= 400) localNon2xx.push({ pathname: url.pathname, status: response.status() });
    });
    page.on("request", (request) => {
      if (request.method() === "POST" && request.url() === `${origin}/api/v1/auth/bootstrap`) bootstrapPosts += 1;
      if (!request.url().startsWith(`${origin}/`) && !request.url().startsWith("data:") && !request.url().startsWith("blob:")) remoteRequests.push("remote-request");
    });

    step = "bootstrap_accessibility";
    await page.goto(origin, { waitUntil: "domcontentloaded" });
    const bootstrapHeading = page.getByRole("heading", { name: "Create the first administrator" });
    await bootstrapHeading.waitFor();
    check(await bootstrapHeading.evaluate((node) => node === document.activeElement), "bootstrap heading receives focus");
    await page.keyboard.press("Tab");
    const tokenInput = page.getByLabel("One-use setup token");
    check(await tokenInput.evaluate((node) => node === document.activeElement), "bootstrap form is keyboard reachable by label");
    check(await tokenInput.evaluate((node) => getComputedStyle(node).outlineStyle !== "none" && getComputedStyle(node).outlineWidth !== "0px"), "keyboard focus indicator is visible");
    const usernameInput = page.getByLabel("Administrator username");
    const passwordInput = page.getByLabel("Password", { exact: true });
    const confirmationInput = page.getByLabel("Confirm password");
    check(await usernameInput.count() === 1 && await passwordInput.count() === 1 && await confirmationInput.count() === 1, "bootstrap controls have accessible labels");

    step = "password_mismatch";
    await tokenInput.fill(bootstrapToken);
    await usernameInput.fill(username);
    await passwordInput.fill(password);
    await confirmationInput.fill(mismatch);
    const createButton = page.getByRole("button", { name: "Create administrator" });
    await createButton.focus();
    await page.keyboard.press("Enter");
    const mismatchAlert = page.getByRole("alert");
    await mismatchAlert.waitFor();
    check((await mismatchAlert.textContent())?.includes("passwords do not match"), "password mismatch is announced as an alert");
    check(bootstrapPosts === 0, "password mismatch stays local and sends no auth write");
    check(await createButton.evaluate((node) => node === document.activeElement), "validation preserves keyboard focus on submit");

    step = "first_admin";
    await confirmationInput.fill(password);
    await createButton.press("Enter");
    const noTarget = page.getByRole("heading", { name: "No Ollama target is configured" });
    await noTarget.waitFor();
    check(bootstrapPosts === 1, "first administrator uses one bootstrap write");
    const monitorHeading = page.getByRole("heading", { name: "Monitor status" });
    check(await monitorHeading.evaluate((node) => node === document.activeElement), "authenticated status heading receives focus");
    check(await page.getByText("None sent by LLM Monitor", { exact: true }).count() === 1, "no inference state is visible");
    check(await page.getByText("Offline help", { exact: true }).count() === 1, "offline help is visible");
    const bodyText = await page.locator("body").innerText();
    check(bodyText.includes("docs/operate.html"), "installed offline guide path is visible");
    check(bodyText.includes(`${INSTALLED_CLI} status`) && bodyText.includes(`${INSTALLED_CLI} install check --role local`), "help commands use the installed executable path");
    check(!bodyText.includes(bootstrapToken) && !bodyText.includes(password) && !bodyText.includes(mismatch), "auth canaries are absent from rendered status");
    check(!page.url().includes(bootstrapToken) && !page.url().includes(password) && !page.url().includes(mismatch), "auth canaries are absent from the URL");
    const storage = await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
    check(storage.local.length === 0 && storage.session.length === 0, "application browser storage stays empty");
    await page.screenshot({ path: screenshot, fullPage: true, animations: "disabled" });
    fs.chmodSync(screenshot, 0o600);
    check(fs.statSync(screenshot).size > 0, "sanitized no-target screenshot captured");

    step = "logout";
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    check(await page.getByText("Signed out.", { exact: true }).count() === 1, "logout returns to sign in with status announcement");

    step = "login";
    const loginUsername = page.getByLabel("Username");
    const loginPassword = page.getByLabel("Password");
    check(await loginUsername.count() === 1 && await loginPassword.count() === 1, "login controls have accessible labels");
    await loginUsername.fill(username);
    await loginPassword.fill(password);
    await page.getByRole("button", { name: "Sign in" }).press("Enter");
    await noTarget.waitFor();
    check(await page.getByText(`Signed in as ${username}`, { exact: false }).count() === 1, "password login restores authenticated status");

    step = "authenticated_reload";
    await page.reload({ waitUntil: "domcontentloaded" });
    await noTarget.waitFor();
    check(await monitorHeading.evaluate((node) => node === document.activeElement), "authenticated reload restores status and heading focus");
    check(await page.getByText("Offline help", { exact: true }).count() === 1, "offline help survives authenticated reload");
    if (collectorBinary) {
      step = "live_native_collection";
      collectorLog = fs.openSync(path.join(runRoot, "collector.log"), "a", 0o600);
      collector = spawn(collectorBinary, ["--installation-root", home, "--runtime-dir", runtime, "serve"],
        { env, stdio: ["ignore", collectorLog, collectorLog] });
      await page.getByRole("heading", { name: "This Mac", exact: true }).waitFor({ timeout: 15_000 });
      check(await page.getByText("Memory pressure", { exact: true }).count() === 1, "native host metrics render after collector starts");
      await page.getByRole("heading", { name: "Recent host CPU observations" }).waitFor();
      check(await page.locator("#foundation-status").count() === 1, "service status remains visible with live collection");
      check(await page.getByText("None sent by LLM Monitor", { exact: true }).count() === 1, "passive browser view does not claim inference");
      await page.screenshot({ path: path.join(runRoot, "live-native.png"), fullPage: true, animations: "disabled" });
      check(fs.statSync(path.join(runRoot, "live-native.png")).size > 0, "real native monitoring screenshot captured");
    }
    const favicon404 = localNon2xx.some(({ pathname, status }) => pathname === "/favicon.ico" && status === 404)
      || consoleErrors.some(({ category, pathname, status }) => category === "resource-load" && pathname === "/favicon.ico" && status === 404);
    const unexpectedResponses = localNon2xx.filter(({ pathname, status }) => !(pathname === "/favicon.ico" && status === 404));
    const unexpectedConsoleErrors = consoleErrors.filter(({ category, pathname, status }) => !(favicon404 && category === "resource-load" && pathname === "/favicon.ico" && status === 404));
    check(pageErrors.length === 0 && unexpectedConsoleErrors.length === 0, "page emitted no unexpected JavaScript or console errors");
    check(unexpectedResponses.length === 0, "page received no unexpected local error responses");
    check(remoteRequests.length === 0, "page made only same-origin requests");
    check(!fs.existsSync(tokenFile), "consumed bootstrap token file is removed");
    check(!fs.existsSync(launchLog), "launchctl guard recorded no invocation");

    report.status = "pass";
  } catch (error) {
    report.failure_step = step;
    report.failure_type = error instanceof Error ? error.name : "UnknownError";
  } finally {
    if (context) await context.close().catch(() => {});
    await stopOwnedChild(collector);
    await stopOwnedChild(hub);
    if (collectorLog !== undefined) fs.closeSync(collectorLog);
    if (hubLog !== undefined) fs.closeSync(hubLog);
    try {
      assertCanariesAbsent(runRoot, [bootstrapToken, password, mismatch]);
      passed.push("auth canaries absent from retained state, browser profile, logs, screenshot, and result inputs");
    } catch {
      report.status = "fail";
      report.failure_step = "retained_auth_canary_scan";
      report.failure_type = "AssertionError";
    }
    if (fs.existsSync(launchLog)) {
      report.status = "fail";
      report.failure_step = "launchctl_guard";
      report.failure_type = "AssertionError";
    }
    report.page_error_count = pageErrors.length;
    report.console_error_count = consoleErrors.length;
    report.console_diagnostics = consoleErrors;
    report.local_non_2xx_responses = localNon2xx;
    report.remote_request_count = remoteRequests.length;
    report.elapsed_seconds = Math.round((Date.now() - started) / 10) / 100;
    report.passed_assertions = passed;
    writePrivateJSON(resultFile, report);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
  process.exitCode = report.status === "pass" ? 0 : 1;
}

async function runWorkerSafely() {
  try {
    await worker();
  } catch (error) {
    const runID = parseOption("--run-id", "invalid");
    const runRoot = path.join(PROJECT, ".work/u02-browser-smoke", runID);
    const report = {
      schema_version: "1.0",
      test: "u02_real_browser",
      run_id: runID,
      status: "fail",
      failure_step: "pre_browser_setup",
      failure_type: error instanceof Error ? error.name : "UnknownError",
      outer_deadline_ms: OUTER_DEADLINE_MS,
      script_sha256: sha256(SCRIPT),
    };
    if (error instanceof PreflightError) {
      report.failure_step = error.step;
      if (error.osErrorCode) report.os_error_code = error.osErrorCode;
      if (error.cliExitCode !== undefined) report.cli_exit_code = error.cliExitCode;
      if (error.cliSafeCode) report.cli_safe_code = error.cliSafeCode;
      if (error.cliMessage) report.cli_message = error.cliMessage;
    }
    writePrivateJSON(path.join(runRoot, "result.json"), report);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exitCode = 1;
  }
}

if (process.argv.includes("--worker")) await runWorkerSafely();
else await outer();
