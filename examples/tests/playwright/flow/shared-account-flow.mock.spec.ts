import { expect, test, type Page } from "@playwright/test";
import { execFile } from "node:child_process";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

interface WorkflowTraceStep {
  step_id?: string;
  step_type?: string;
  output_digests?: string[];
  receipt_digests?: string[];
}

interface SigningLink {
  role?: string;
  token?: string;
  url_path?: string;
  signing_package_digest?: string;
}

interface WorkflowRun {
  run_id?: string;
  status?: string;
  final_digest?: string;
  pii_access_count?: number;
  pii_last_receipt_digest?: string;
  pii_audit_head_hash?: string;
  signing_links?: SigningLink[];
  trace_steps?: WorkflowTraceStep[];
}

interface BundleExportResponse {
  run_id: string;
  bundle_path: string;
  manifest_digest: string;
  final_digest: string;
}

const WORKFLOW_BASE_URL = process.env.WORKFLOW_BASE_URL ?? "http://localhost:8080";
const DEMO_DIR = path.resolve(process.cwd(), "..", "..");
const execFileAsync = promisify(execFile);

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function toBundleArg(bundlePath: string): string {
  if (bundlePath.startsWith("/app/")) {
    return bundlePath.slice("/app/".length);
  }
  return bundlePath;
}

async function requestJson<T>(pathname: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${WORKFLOW_BASE_URL}${pathname}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {})
    }
  });

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}: ${await response.text()}`);
  }

  return (await response.json()) as T;
}

async function getRun(runId: string): Promise<WorkflowRun> {
  return requestJson<WorkflowRun>(`/workflow/runs/${encodeURIComponent(runId)}`);
}

async function waitForRunSigningLinks(runId: string): Promise<WorkflowRun> {
  await expect
    .poll(async () => {
      const runs = await requestJson<WorkflowRun[]>("/workflow/runs");
      const run = runs.find((candidate) => asString(candidate.run_id) === runId);
      return Array.isArray(run?.signing_links) ? run.signing_links.length : 0;
    }, {
      timeout: 30_000,
      message: `expected signing links for run ${runId}`
    })
    .toBe(2);

  return getRun(runId);
}

async function runMakeTarget(target: "replay" | "replay-negative", bundleArg: string): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync(
      "make",
      [target, `BUNDLE=${bundleArg}`],
      {
        cwd: DEMO_DIR,
        maxBuffer: 20 * 1024 * 1024
      }
    );

    return `${stdout}\n${stderr}`;
  } catch (error) {
    const err = error as Error & { stdout?: string; stderr?: string };
    const combined = `${err.stdout ?? ""}\n${err.stderr ?? ""}`;
    if (target === "replay") {
      throw new Error(`make replay failed:\n${combined}`);
    }
    return combined;
  }
}

async function signViaPublicPage(page: Page, urlPath: string): Promise<void> {
  await page.goto(urlPath);
  await expect(page.getByTestId("step-token-status")).toHaveText("DONE");

  await page.getByTestId("sign-button").click();

  await expect(page.getByTestId("sign-success-banner")).toBeVisible();
  await expect(page.getByTestId("step-bankid-start-status")).toHaveText("DONE");
  await expect(page.getByTestId("step-bankid-collect-status")).toHaveText("DONE");
  await expect(page.getByTestId("step-workflow-submit-status")).toHaveText("DONE");
  await expect(page.getByTestId("step-workflow-run-status")).toHaveText("DONE");
}

async function captureFailureScreenshot(page: Page, fileName: string): Promise<void> {
  const artifactsDir = path.resolve(process.cwd(), "artifacts");
  await mkdir(artifactsDir, { recursive: true });
  await page.screenshot({
    path: path.join(artifactsDir, fileName),
    fullPage: true
  });
}

test("shared account flow reaches PASS with mainframe receipt and offline replay proof", async ({ page }, testInfo) => {
  try {
    await expect
      .poll(async () => {
        try {
          await requestJson<{ status: string }>("/workflow/health");
          return "up";
        } catch {
          return "down";
        }
      }, {
        timeout: 20_000,
        message: "workflow stack is not reachable; run `cd demo && make up` first"
      })
      .toBe("up");

    const ingestPayload = {
      event: {
        customer_id: "190000000000",
        change_type: "shared_account.open",
        new_value: "joint-account-v1",
        correlation_id: "pw-shared-account-flow-v0"
      }
    };

    const created = await requestJson<WorkflowRun>("/workflow/ingest", {
      method: "POST",
      body: JSON.stringify(ingestPayload),
      headers: {
        "Content-Type": "application/json"
      }
    });

    const runId = asString(created.run_id);
    expect(runId).toMatch(/^run-[0-9a-f]{16}$/);

    const runWithLinks = await waitForRunSigningLinks(runId);
    const links = Array.isArray(runWithLinks.signing_links) ? runWithLinks.signing_links : [];
    const parentLink = links.find((link) => asString(link.role) === "parent");
    const childLink = links.find((link) => asString(link.role) === "child");

    const parentUrlPath = asString(parentLink?.url_path);
    const childUrlPath = asString(childLink?.url_path);

    expect(parentUrlPath).toMatch(/^\/ui\/sign\/parent\//);
    expect(childUrlPath).toMatch(/^\/ui\/sign\/child\//);

    await signViaPublicPage(page, parentUrlPath);
    await signViaPublicPage(page, childUrlPath);

    await expect
      .poll(async () => {
        const run = await getRun(runId);
        return `${asString(run.status)}|${asString(run.final_digest)}`;
      }, {
        timeout: 40_000,
        message: "expected finalized PASS run"
      })
      .toMatch(/^PASS\|[0-9a-f]{64}$/);

    const finalRun = await getRun(runId);
    const mainframeStep = (finalRun.trace_steps ?? []).find(
      (step) => step.step_type === "mainframe_open_account"
    );
    expect(mainframeStep?.output_digests?.[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(mainframeStep?.receipt_digests?.[0]).toMatch(/^sha256:[0-9a-f]{64}$/);

    await page.goto(`/ui/runs/${encodeURIComponent(runId)}`);
    await expect(page.locator("tbody tr", { hasText: "signature_gate_parent" })).toContainText("ok");
    await expect(page.locator("tbody tr", { hasText: "signature_gate_child" })).toContainText("ok");
    await expect(page.locator("tbody tr", { hasText: "mainframe_open_account" })).toContainText("ok");
    await expect(page.locator("tbody tr", { hasText: "finalize" })).toContainText("ok");
    await expect(page.locator("body")).toContainText("PASS");

    await page.getByTestId("pii-reveal-button").click();
    await expect(page.getByTestId("pii-access-count-value")).toHaveText("1");
    await expect(page.getByTestId("pii-receipt-digest-value")).toHaveText(/^sha256:[0-9a-f]{64}$/);
    await expect(page.getByTestId("pii-audit-head-hash-value")).toHaveText(/^[0-9a-f]{64}$/);

    await page.getByTestId("pii-audit-tab").click();
    await expect
      .poll(async () => page.getByTestId("pii-audit-row").count(), {
        timeout: 20_000,
        message: "expected at least one PII audit row after reveal"
      })
      .toBeGreaterThan(0);
    await expect(page.getByTestId("pii-audit-row").first().getByTestId("pii-audit-decision-cell")).toHaveText("ALLOW");
    await expect(page.getByTestId("pii-audit-chain-head-value")).toContainText(/[0-9a-f]{12}/);
    await expect(page.getByTestId("pii-audit-chain-status-value")).toContainText("VERIFIED");

    await page
      .getByTestId("pii-audit-row")
      .first()
      .getByTestId("pii-audit-receipt-cell")
      .getByRole("button", { name: "Open digest" })
      .click();
    await expect(page.getByRole("heading", { name: "Artifact Viewer" })).toBeVisible();
    await page.getByRole("button", { name: "Close" }).click();

    await page.getByTestId("pii-audit-view-chain-button").click();
    await expect(page.getByTestId("pii-ledger-chain-dialog-title")).toBeVisible();
    await expect(page.getByTestId("pii-ledger-chain-jsonl")).toBeVisible();
    await page.getByRole("button", { name: "Close" }).click();

    const runAfterPiiReveal = await getRun(runId);
    expect(runAfterPiiReveal.pii_access_count).toBe(1);
    expect(asString(runAfterPiiReveal.pii_last_receipt_digest)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(asString(runAfterPiiReveal.pii_audit_head_hash)).toMatch(/^[0-9a-f]{64}$/);

    const exported = await requestJson<BundleExportResponse>(
      `/workflow/bundles/${encodeURIComponent(runId)}/export`
    );

    expect(exported.run_id).toBe(runId);
    expect(exported.manifest_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(exported.final_digest).toMatch(/^[0-9a-f]{64}$/);

    const bundleArg = toBundleArg(exported.bundle_path);
    const replayOutput = await runMakeTarget("replay", bundleArg);
    expect(replayOutput).toContain('"match":true');

    const replayNegativeOutput = await runMakeTarget("replay-negative", bundleArg);
    expect(replayNegativeOutput).toContain("step_id=PII-AUDIT step_type=pii_audit_chain_verify");
    expect(replayNegativeOutput).toContain("replay mismatch");
  } catch (error) {
    await captureFailureScreenshot(
      page,
      `shared-account-flow.mock.retry-${testInfo.retry}.failure.png`
    );
    throw error;
  }
});
