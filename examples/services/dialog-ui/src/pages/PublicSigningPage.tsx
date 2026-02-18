import { Alert, Button, Card, Flex, Space, Spin, Tag, Typography } from "antd";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import {
  BankIdCollectResponse,
  WorkflowRun,
  collectBankIdSign,
  getRun,
  resolveSigningToken,
  startBankIdSign,
  submitSignatureReceipt
} from "../api/workflow";

type SignerRole = "parent" | "child";
type StepState = "pending" | "active" | "done" | "failed";
type StepId = "token" | "bankid-start" | "bankid-collect" | "workflow-submit" | "workflow-run";

interface PublicSigningPageProps {
  role: SignerRole;
}

interface SigningTokenState {
  token: string;
  run_id: string;
  signer_role: SignerRole;
  signing_package_digest: string;
  end_user_ip?: string;
  user_visible_text?: string;
}

const stepSequence: Array<{ id: StepId; label: string }> = [
  { id: "token", label: "Resolve token" },
  { id: "bankid-start", label: "Start BankID" },
  { id: "bankid-collect", label: "Collect BankID receipt" },
  { id: "workflow-submit", label: "Submit workflow receipt" },
  { id: "workflow-run", label: "Verify run trace update" }
];

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, milliseconds);
  });
}

function normalizeSignerRole(value: string, fallback: SignerRole): SignerRole {
  return value === "child" ? "child" : fallback;
}

function toBase64Utf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window.btoa(binary);
}

function runContainsReceiptDigest(run: WorkflowRun, receiptDigest: string): boolean {
  const runLevel = run.receipt_digests?.includes(receiptDigest) ?? false;
  if (runLevel) {
    return true;
  }

  return (run.trace_steps ?? []).some((step) => step.receipt_digests?.includes(receiptDigest));
}

function stepColor(state: StepState): "processing" | "default" | "success" | "error" {
  if (state === "active") {
    return "processing";
  }
  if (state === "done") {
    return "success";
  }
  if (state === "failed") {
    return "error";
  }
  return "default";
}

function stepLabel(state: StepState): string {
  return state.toUpperCase();
}

async function collectUntilComplete(orderRef: string): Promise<BankIdCollectResponse> {
  const maxAttempts = 40;
  const intervalMs = 500;
  let lastStatus = "pending";

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const response = await collectBankIdSign(orderRef);
    lastStatus = String(response.status ?? "");

    if (response.status === "complete") {
      return response;
    }

    if (response.status === "failed") {
      throw new Error(`BankID collect failed (${response.hint_code ?? "no hint code"})`);
    }

    await delay(intervalMs);
  }

  throw new Error(`BankID collect timed out with last status "${lastStatus}"`);
}

export function PublicSigningPage({ role }: PublicSigningPageProps): JSX.Element {
  const params = useParams<{ token: string }>();
  const routeToken = useMemo(() => decodeURIComponent(params.token ?? ""), [params.token]);

  const [signingToken, setSigningToken] = useState<SigningTokenState | null>(null);
  const [stepState, setStepState] = useState<Record<StepId, StepState>>({
    token: "active",
    "bankid-start": "pending",
    "bankid-collect": "pending",
    "workflow-submit": "pending",
    "workflow-run": "pending"
  });
  const [loadingToken, setLoadingToken] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [receiptDigest, setReceiptDigest] = useState<string | null>(null);
  const [runReceiptReflected, setRunReceiptReflected] = useState<boolean | null>(null);
  const [autoStartToken, setAutoStartToken] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  function updateStep(id: StepId, state: StepState): void {
    setStepState((prev) => ({
      ...prev,
      [id]: state
    }));
  }

  useEffect(() => {
    if (!routeToken) {
      setError("Missing signing token in route.");
      setLoadingToken(false);
      updateStep("token", "failed");
      return;
    }

    let active = true;
    setLoadingToken(true);
    setError(null);

    resolveSigningToken(routeToken)
      .then((resolved) => {
        if (!active) {
          return;
        }

        const runId = typeof resolved.run_id === "string" ? resolved.run_id : "";
        const signingPackageDigest =
          typeof resolved.signing_package_digest === "string" ? resolved.signing_package_digest : "";

        if (!runId || !signingPackageDigest) {
          throw new Error("Token response is missing run_id or signing_package_digest.");
        }

        setSigningToken({
          token: typeof resolved.token === "string" ? resolved.token : routeToken,
          run_id: runId,
          signer_role: normalizeSignerRole(String(resolved.signer_role), role),
          signing_package_digest: signingPackageDigest,
          end_user_ip: typeof resolved.end_user_ip === "string" ? resolved.end_user_ip : undefined,
          user_visible_text:
            typeof resolved.user_visible_text === "string" ? resolved.user_visible_text : undefined
        });
        updateStep("token", "done");
      })
      .catch((reason: Error) => {
        if (!active) {
          return;
        }

        setSigningToken(null);
        setError(`Token lookup failed: ${reason.message}`);
        updateStep("token", "failed");
      })
      .finally(() => {
        if (active) {
          setLoadingToken(false);
        }
      });

    return () => {
      active = false;
    };
  }, [role, routeToken]);

  async function runSignFlow(): Promise<void> {
    if (!signingToken) {
      return;
    }

    setError(null);
    setSuccess(false);
    setRunReceiptReflected(null);
    setReceiptDigest(null);
    setAutoStartToken(null);
    setIsSubmitting(true);
    updateStep("bankid-start", "pending");
    updateStep("bankid-collect", "pending");
    updateStep("workflow-submit", "pending");
    updateStep("workflow-run", "pending");

    let activeStep: StepId = "bankid-start";

    try {
      updateStep("bankid-start", "active");
      const startResponse = await startBankIdSign({
        signing_package_digest: signingToken.signing_package_digest,
        signer_role: signingToken.signer_role,
        end_user_ip: signingToken.end_user_ip ?? "127.0.0.1",
        user_visible_text:
          signingToken.user_visible_text ??
          toBase64Utf8(
            `Rulia signing request ${signingToken.signer_role} ${signingToken.signing_package_digest}`
          )
      });

      if (typeof startResponse.order_ref !== "string" || startResponse.order_ref.length === 0) {
        throw new Error("BankID start response did not include order_ref");
      }

      setAutoStartToken(
        typeof startResponse.auto_start_token === "string" ? startResponse.auto_start_token : null
      );
      updateStep("bankid-start", "done");

      activeStep = "bankid-collect";
      updateStep("bankid-collect", "active");
      const collectResponse = await collectUntilComplete(startResponse.order_ref);
      const receivedDigest =
        typeof collectResponse.receipt_digest === "string" ? collectResponse.receipt_digest : "";
      const receivedReceipt =
        collectResponse.receipt && typeof collectResponse.receipt === "object"
          ? collectResponse.receipt
          : null;

      if (!receivedDigest || !receivedReceipt) {
        throw new Error("BankID collect did not return receipt and receipt_digest");
      }

      setReceiptDigest(receivedDigest);
      updateStep("bankid-collect", "done");

      activeStep = "workflow-submit";
      updateStep("workflow-submit", "active");
      const submitResponse = await submitSignatureReceipt({
        token: signingToken.token,
        run_id: signingToken.run_id,
        signer_role: signingToken.signer_role,
        receipt: receivedReceipt,
        receipt_digest: receivedDigest
      });

      updateStep("workflow-submit", "done");

      const runId =
        typeof submitResponse.run_id === "string" && submitResponse.run_id.length > 0
          ? submitResponse.run_id
          : signingToken.run_id;

      activeStep = "workflow-run";
      updateStep("workflow-run", "active");
      const run = await getRun(runId);
      const reflected = runContainsReceiptDigest(run, receivedDigest);
      setRunReceiptReflected(reflected);
      updateStep("workflow-run", reflected ? "done" : "failed");
      if (!reflected) {
        throw new Error("Submitted receipt digest is not present in workflow run trace.");
      }

      setSuccess(true);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setError(message);
      updateStep(activeStep, "failed");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="page-stack">
      <Card className="card-muted">
        <Space direction="vertical" size={6}>
          <Flex align="center" gap={8}>
            <Tag color={role === "parent" ? "geekblue" : "purple"}>
              {role === "parent" ? "PARENT" : "CHILD"}
            </Tag>
            <Typography.Title level={3} style={{ margin: 0 }}>
              {role === "parent" ? "Parent signing" : "Child signing"}
            </Typography.Title>
          </Flex>
          <Typography.Text type="secondary">
            Public signing flow for token-bound BankID signatures and workflow receipt submission.
          </Typography.Text>
        </Space>
      </Card>

      <Card className="card-muted" title="Signing request">
        <Space direction="vertical" size={10} style={{ width: "100%" }}>
          <div className="key-value-grid">
            <span className="key-label">Route token</span>
            <span className="key-value monospace">{routeToken || "-"}</span>
          </div>
          <div className="key-value-grid">
            <span className="key-label">Run ID</span>
            <span className="key-value monospace" data-testid="run-id-value">
              {signingToken?.run_id ?? "-"}
            </span>
          </div>
          <div className="key-value-grid">
            <span className="key-label">Signing package digest</span>
            <span className="key-value monospace">{signingToken?.signing_package_digest ?? "-"}</span>
          </div>
          <div className="key-value-grid">
            <span className="key-label">Signer role</span>
            <span className="key-value">{signingToken?.signer_role ?? role}</span>
          </div>
          <Space wrap>
            <Button
              type="primary"
              disabled={loadingToken || !signingToken || isSubmitting}
              onClick={() => void runSignFlow()}
              data-testid="sign-button"
            >
              Sign with BankID
            </Button>
            {loadingToken ? (
              <Space>
                <Spin size="small" />
                <Typography.Text>Resolving token</Typography.Text>
              </Space>
            ) : null}
            {isSubmitting ? (
              <Space>
                <Spin size="small" />
                <Typography.Text>Signing in progress</Typography.Text>
              </Space>
            ) : null}
          </Space>
        </Space>
      </Card>

      {autoStartToken ? (
        <Card className="card-subtle">
          <Typography.Text type="secondary">
            BankID auto-start token: <span data-testid="auto-start-token-value">{autoStartToken}</span>
          </Typography.Text>
        </Card>
      ) : null}

      {success ? (
        <div role="status" data-testid="sign-success-banner">
          <Alert
            type="success"
            showIcon
            message="Signature receipt submitted and validated against workflow run trace."
          />
        </div>
      ) : null}

      {error ? (
        <div role="alert" data-testid="sign-error-banner">
          <Alert type="error" showIcon message={error} />
        </div>
      ) : null}

      <Card className="card-muted" title="Submission verification">
        <Space direction="vertical" size={10} style={{ width: "100%" }}>
          <div className="key-value-grid">
            <span className="key-label">Receipt digest</span>
            <span className="key-value monospace" data-testid="receipt-digest-value">
              {receiptDigest ?? "-"}
            </span>
          </div>
          <div className="key-value-grid">
            <span className="key-label">Run trace status</span>
            <span className="key-value" data-testid="run-trace-receipt-status">
              {runReceiptReflected === null
                ? "-"
                : runReceiptReflected
                  ? "Receipt present in run trace"
                  : "Receipt missing from run trace"}
            </span>
          </div>
        </Space>
      </Card>

      <Card className="card-muted" title="Step status">
        {stepSequence.map((step) => (
          <div key={step.id} className="step-status-row">
            <Typography.Text>{step.label}</Typography.Text>
            <Tag color={stepColor(stepState[step.id])} data-testid={`step-${step.id}-status`}>
              {stepLabel(stepState[step.id])}
            </Tag>
          </div>
        ))}
      </Card>
    </div>
  );
}
