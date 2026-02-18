import { expect, Page } from "@playwright/test";

type SignerRole = "parent" | "child";

interface SigningFixture {
  role: SignerRole;
  token: string;
  runId: string;
  signingPackageDigest: string;
  adapterReceiptDigest: string | null;
  submitBodies: Array<Record<string, unknown>>;
}

interface WorkflowTraceStep {
  step_id?: string;
  step_type?: string;
  output_digests?: string[];
  receipt_digests?: string[];
}

interface WorkflowRun {
  run_id?: string;
  signing_package_digest?: string;
  signing_links?: Array<Record<string, unknown>>;
  trace_steps?: WorkflowTraceStep[];
}

const WORKFLOW_BASE_URL = process.env.WORKFLOW_BASE_URL ?? "http://localhost:8080";

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
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

function toStringOrEmpty(value: unknown): string {
  return typeof value === "string" ? value : "";
}

async function getRun(runId: string): Promise<WorkflowRun> {
  return requestJson<WorkflowRun>(
    `${WORKFLOW_BASE_URL}/workflow/runs/${encodeURIComponent(runId)}`
  );
}

async function seedSigningRun(role: SignerRole): Promise<SigningFixture> {
  const seed = `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  const event = {
    customer_id: role === "parent" ? "190000000000" : "191111111111",
    change_type: "address",
    new_value: `Kungsgatan ${seed}`,
    correlation_id: `pw-sign-${role}-${seed}`
  };

  const run = await requestJson<WorkflowRun>(`${WORKFLOW_BASE_URL}/workflow/ingest`, {
    method: "POST",
    body: JSON.stringify({ event }),
    headers: {
      "Content-Type": "application/json"
    }
  });

  const runId = toStringOrEmpty(run.run_id);
  if (!runId) {
    throw new Error("workflow ingest response missing run_id");
  }

  const links = Array.isArray(run.signing_links) ? run.signing_links : [];
  const link = links.find((candidate) => toStringOrEmpty(candidate.role) === role);
  const token = toStringOrEmpty(link?.token);
  const signingPackageDigest =
    toStringOrEmpty(link?.signing_package_digest) || toStringOrEmpty(run.signing_package_digest);

  if (!token || !signingPackageDigest) {
    throw new Error(`workflow run ${runId} missing signing link for role ${role}`);
  }

  return {
    role,
    token,
    runId,
    signingPackageDigest,
    adapterReceiptDigest: null,
    submitBodies: []
  };
}

function captureCompleteCollectResponses(page: Page, fixture: SigningFixture): void {
  page.on("response", async (response) => {
    if (!response.url().includes("/bankid/sign/collect")) {
      return;
    }

    try {
      const payload = (await response.json()) as Record<string, unknown>;
      if (payload.status !== "complete") {
        return;
      }
      if (typeof payload.receipt_digest === "string") {
        fixture.adapterReceiptDigest = payload.receipt_digest;
      }
    } catch {
      // Ignore non-JSON collect responses in diagnostics flows.
    }
  });
}

function captureSubmitBodies(page: Page, fixture: SigningFixture): void {
  page.on("request", (request) => {
    if (
      request.method() !== "POST" ||
      !request.url().includes("/workflow/signatures/submit")
    ) {
      return;
    }

    const raw = request.postData() ?? "{}";
    try {
      fixture.submitBodies.push(JSON.parse(raw) as Record<string, unknown>);
    } catch {
      fixture.submitBodies.push({ invalid_json: raw });
    }
  });
}

async function assertGateStepReflected(
  runId: string,
  role: SignerRole,
  expectedReceiptDigest: string
): Promise<void> {
  const run = await getRun(runId);
  const gateStepId = role === "parent" ? "S5b" : "S5c";
  const step = (run.trace_steps ?? []).find((candidate) => candidate.step_id === gateStepId);
  expect(step?.step_type).toBe(
    role === "parent" ? "signature_gate_parent" : "signature_gate_child"
  );
  expect(step?.receipt_digests ?? []).toContain(expectedReceiptDigest);
  expect(step?.output_digests ?? []).toHaveLength(1);
  expect(step?.output_digests?.[0]).toMatch(/^[0-9a-f]{64}$/);
}

export async function runMockSigningFlow(page: Page, role: SignerRole): Promise<void> {
  const fixture = await seedSigningRun(role);
  captureCompleteCollectResponses(page, fixture);
  captureSubmitBodies(page, fixture);

  await page.goto(`/ui/sign/${role}/${fixture.token}`);
  await expect(page).toHaveURL(new RegExp(`/ui/sign/${role}/${fixture.token}$`));
  await expect(page.getByTestId("step-token-status")).toHaveText("DONE");
  await expect(page.getByTestId("run-id-value")).toHaveText(fixture.runId);

  await page.getByTestId("sign-button").click();

  await expect(page.getByTestId("sign-success-banner")).toBeVisible();
  await expect(page.getByTestId("step-bankid-start-status")).toHaveText("DONE");
  await expect(page.getByTestId("step-bankid-collect-status")).toHaveText("DONE");
  await expect(page.getByTestId("step-workflow-submit-status")).toHaveText("DONE");
  await expect(page.getByTestId("step-workflow-run-status")).toHaveText("DONE");
  await expect(page.getByTestId("run-trace-receipt-status")).toHaveText(
    "Receipt present in run trace"
  );

  await expect
    .poll(() => fixture.adapterReceiptDigest, {
      message: "expected collect to return a complete receipt digest",
      timeout: 25_000
    })
    .toMatch(/^sha256:[0-9a-f]{64}$/);

  const receiptDigest = fixture.adapterReceiptDigest as string;
  await expect(page.getByTestId("receipt-digest-value")).toHaveText(receiptDigest);

  expect(fixture.submitBodies).toHaveLength(1);
  expect(fixture.submitBodies[0].signer_role).toBe(role);
  expect(fixture.submitBodies[0].run_id).toBe(fixture.runId);
  expect(fixture.submitBodies[0].receipt_digest).toBe(receiptDigest);
  await assertGateStepReflected(fixture.runId, role, receiptDigest);
}

export async function runOptionalRealModeFlow(page: Page, role: SignerRole): Promise<void> {
  const fixture = await seedSigningRun(role);
  captureCompleteCollectResponses(page, fixture);

  await page.goto(`/ui/sign/${role}/${fixture.token}`);
  await expect(page.getByTestId("step-token-status")).toHaveText("DONE");

  await page.getByTestId("sign-button").click();
  await expect(page.getByTestId("sign-success-banner")).toBeVisible({
    timeout: 120_000
  });
}
