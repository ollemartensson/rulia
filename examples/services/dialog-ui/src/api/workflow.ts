export interface WorkflowTraceStep {
  step_id: string;
  step_type: string;
  input_digests?: string[];
  output_digests?: string[];
  obligation_digests?: string[];
  receipt_digests?: string[];
  [key: string]: unknown;
}

export interface WorkflowPiiAccess {
  receipt_digest?: string;
  receipt_artifact_digest?: string;
  ledger_receipt_digest?: string;
  ledger_receipt_artifact_digest?: string;
  decision?: string;
  actor_type?: string;
  actor_id?: string;
  purpose?: string;
  fields?: string[];
  subject_id?: string;
  pii_ref?: string;
  audit_event_hash?: string;
  head_hash?: string;
  audit_head_hash?: string;
  [key: string]: unknown;
}

export interface WorkflowRun {
  run_id: string;
  status: string;
  input_digest?: string;
  validation_digest?: string;
  obligation_digests?: string[];
  receipt_digests?: string[];
  final_digest?: string;
  trace_steps?: WorkflowTraceStep[];
  trace_step_count?: number;
  steps_verified?: number;
  created?: string;
  created_at?: string;
  pii_access_count?: number;
  pii_last_receipt_digest?: string;
  pii_last_ledger_receipt_digest?: string;
  pii_last_audit_event_hash?: string;
  pii_audit_head_hash?: string;
  audit_chain_head_hash?: string;
  pii_access_receipt_digests?: string[];
  pii_accesses?: WorkflowPiiAccess[];
  [key: string]: unknown;
}

export interface LedgerChainEvent {
  sequence?: number;
  prev_hash?: string;
  event_hash?: string;
  event?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface LedgerChainResponse {
  raw_jsonl: string;
  events: LedgerChainEvent[];
}

export interface BundleExportResponse {
  run_id: string;
  bundle_path: string;
  manifest_digest: string;
  final_digest: string;
}

export interface SigningTokenResolution {
  token: string;
  run_id: string;
  signer_role: "parent" | "child";
  signing_package_digest: string;
  end_user_ip?: string;
  user_visible_text?: string;
  [key: string]: unknown;
}

export interface BankIdStartRequest {
  signing_package_digest: string;
  signer_role: "parent" | "child";
  end_user_ip: string;
  user_visible_text: string;
}

export interface BankIdStartResponse {
  order_ref: string;
  auto_start_token: string;
  status: "pending" | "failed" | string;
  [key: string]: unknown;
}

export interface BankIdCollectResponse {
  status: "pending" | "complete" | "failed" | string;
  hint_code?: string;
  receipt?: Record<string, unknown>;
  receipt_digest?: string;
  [key: string]: unknown;
}

export interface SignatureSubmitResponse {
  run_id?: string;
  status?: string;
  [key: string]: unknown;
}

export interface PiiRevealResponse {
  status: string;
  run_id: string;
  subject_id: string;
  receipt_digest: string;
  ledger_receipt_digest: string;
  audit_event_hash: string;
  audit_head_hash: string;
  pii_access_count: number;
  [key: string]: unknown;
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    cache: "no-store",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {})
    }
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${detail}`);
  }

  return (await response.json()) as T;
}

async function requestText(url: string, init?: RequestInit): Promise<string> {
  const response = await fetch(url, {
    cache: "no-store",
    ...init,
    headers: {
      Accept: "application/x-ndjson, text/plain, application/json",
      ...(init?.headers ?? {})
    }
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${detail}`);
  }

  return response.text();
}

function postJson<T>(url: string, payload: unknown): Promise<T> {
  return requestJson<T>(url, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: {
      "Content-Type": "application/json"
    }
  });
}

export async function getRuns(): Promise<WorkflowRun[]> {
  const runs = await requestJson<WorkflowRun[]>("/workflow/runs");

  return [...runs].sort((a, b) => {
    const createdA = String(a.created_at ?? a.created ?? "");
    const createdB = String(b.created_at ?? b.created ?? "");

    if (createdA && createdB && createdA !== createdB) {
      return createdB.localeCompare(createdA);
    }

    return b.run_id.localeCompare(a.run_id);
  });
}

export function getRun(runId: string): Promise<WorkflowRun> {
  return requestJson<WorkflowRun>(`/workflow/runs/${encodeURIComponent(runId)}`);
}

export function resolveSigningToken(token: string): Promise<SigningTokenResolution> {
  return requestJson<SigningTokenResolution>(
    `/workflow/signing/token/${encodeURIComponent(token)}`
  );
}

export function startBankIdSign(payload: BankIdStartRequest): Promise<BankIdStartResponse> {
  return postJson<BankIdStartResponse>("/bankid/sign/start", payload);
}

export function collectBankIdSign(orderRef: string): Promise<BankIdCollectResponse> {
  return postJson<BankIdCollectResponse>("/bankid/sign/collect", {
    order_ref: orderRef
  });
}

export function submitSignatureReceipt(payload: {
  token: string;
  run_id: string;
  signer_role: "parent" | "child";
  receipt: Record<string, unknown>;
  receipt_digest: string;
}): Promise<SignatureSubmitResponse> {
  return postJson<SignatureSubmitResponse>("/workflow/signatures/submit", payload);
}

export function revealPiiForRun(
  runId: string,
  payload: {
    actor_type?: string;
    actor_id?: string;
    purpose?: string;
    fields?: string[];
    subject_id?: string;
  } = {}
): Promise<PiiRevealResponse> {
  return postJson<PiiRevealResponse>(`/workflow/runs/${encodeURIComponent(runId)}/pii/reveal`, payload);
}

export function getArtifact(digest: string): Promise<unknown> {
  return requestJson<unknown>(`/workflow/artifacts/${digest}`);
}

export async function getLedgerChain(headHash: string): Promise<LedgerChainResponse> {
  const raw = await requestText(`/ledger/chain?head_hash=${encodeURIComponent(headHash)}`);
  const events: LedgerChainEvent[] = [];

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    const parsed = JSON.parse(trimmed) as LedgerChainEvent;
    events.push(parsed);
  }

  return {
    raw_jsonl: raw,
    events
  };
}

export function exportBundle(runId: string): Promise<BundleExportResponse> {
  return requestJson<BundleExportResponse>(
    `/workflow/bundles/${encodeURIComponent(runId)}/export`
  );
}

export function digestCount(list: string[] | undefined): number {
  return list?.length ?? 0;
}

export function deriveStepResult(
  runStatus: string,
  step: WorkflowTraceStep,
  index: number,
  totalSteps: number
): "ok" | "pending" | "fail" {
  if ((step.output_digests?.length ?? 0) > 0) {
    return "ok";
  }

  if (runStatus !== "PASS" && index === totalSteps - 1) {
    return "fail";
  }

  return "pending";
}

export function displayCreated(run: WorkflowRun, order: number): string {
  const explicit = run.created_at ?? run.created;
  if (typeof explicit === "string" && explicit.length > 0) {
    return explicit;
  }
  return `order:${order}`;
}

export function stepsVerified(run: WorkflowRun): number {
  if (typeof run.steps_verified === "number") {
    return run.steps_verified;
  }

  return (run.trace_steps ?? []).filter((step) => (step.output_digests?.length ?? 0) > 0)
    .length;
}
