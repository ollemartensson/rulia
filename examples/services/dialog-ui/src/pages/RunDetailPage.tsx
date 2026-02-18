import { ArrowLeftOutlined } from "@ant-design/icons";
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Flex,
  Space,
  Spin,
  Tabs,
  Tag,
  Typography,
  message,
  type DescriptionsProps
} from "antd";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { getRun, revealPiiForRun, WorkflowRun, WorkflowTraceStep } from "../api/workflow";
import { DigestPill } from "../components/DigestPill";
import { PiiAuditPanel } from "../components/PiiAuditPanel";
import { ReplayActions } from "../components/ReplayActions";
import { StepDetailDialog } from "../components/StepDetailDialog";
import { StepTraceTable } from "../components/StepTraceTable";

const runTabs = ["trace", "pii-audit"] as const;
type RunTab = (typeof runTabs)[number];

function runTraceCount(run: WorkflowRun): number {
  if (typeof run.trace_step_count === "number") {
    return run.trace_step_count;
  }
  return run.trace_steps?.length ?? 0;
}

export function RunDetailPage(): JSX.Element {
  const params = useParams<{ runId: string }>();
  const navigate = useNavigate();

  const runId = useMemo(() => decodeURIComponent(params.runId ?? ""), [params.runId]);
  const [run, setRun] = useState<WorkflowRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedStep, setSelectedStep] = useState<WorkflowTraceStep | null>(null);
  const [stepDialogOpen, setStepDialogOpen] = useState(false);
  const [revealingPii, setRevealingPii] = useState(false);
  const [revealError, setRevealError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<RunTab>("trace");

  useEffect(() => {
    if (!runId) {
      setError("run id is required");
      setLoading(false);
      return;
    }

    let active = true;
    let pollHandle: number | null = null;

    async function loadRun(initial: boolean): Promise<void> {
      if (initial) {
        setLoading(true);
        setError(null);
      }

      try {
        const data = await getRun(runId);
        if (!active) {
          return;
        }
        setRun(data);
        setError(null);
      } catch (err) {
        if (!active) {
          return;
        }
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg);
      } finally {
        if (active && initial) {
          setLoading(false);
        }
      }
    }

    void loadRun(true);
    pollHandle = window.setInterval(() => {
      void loadRun(false);
    }, 2000);

    return () => {
      active = false;
      if (pollHandle !== null) {
        window.clearInterval(pollHandle);
      }
    };
  }, [runId]);

  async function copyDigest(digest: string): Promise<void> {
    await navigator.clipboard.writeText(digest);
    message.success("Digest copied");
  }

  async function revealPii(): Promise<void> {
    if (!run || revealingPii) {
      return;
    }

    setRevealError(null);
    setRevealingPii(true);
    try {
      const response = await revealPiiForRun(run.run_id, {
        actor_type: "human",
        actor_id: "internal-ui-operator",
        purpose: "run-detail-review",
        fields: ["full_name", "email", "phone"]
      });
      message.success(`PII reveal audited (${response.receipt_digest})`);

      const updated = await getRun(run.run_id);
      setRun(updated);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setRevealError(msg);
      message.error("PII reveal failed");
    } finally {
      setRevealingPii(false);
    }
  }

  const detailItems = useMemo<DescriptionsProps["items"]>(() => {
    if (!run) {
      return [];
    }

    return [
      {
        key: "run-id",
        label: "Run ID",
        children: <span className="key-value monospace">{run.run_id}</span>
      },
      {
        key: "status",
        label: "Status",
        children: <Tag color={run.status === "PASS" ? "success" : "warning"}>{run.status}</Tag>
      },
      {
        key: "final",
        label: "Final PASS digest",
        children: run.final_digest ? (
          <DigestPill digest={run.final_digest} onCopy={(digest) => void copyDigest(digest)} />
        ) : (
          "-"
        )
      },
      {
        key: "bundle",
        label: "Bundle export path",
        children:
          typeof run.bundle_path === "string"
            ? run.bundle_path
            : "Use Export bundle below to generate and view path."
      },
      {
        key: "trace-count",
        label: "Trace step count",
        children: runTraceCount(run)
      },
      {
        key: "pii-count",
        label: "PII access count",
        children: (
          <span data-testid="pii-access-count-value">
            {typeof run.pii_access_count === "number" ? run.pii_access_count : 0}
          </span>
        )
      },
      {
        key: "pii-receipt",
        label: "Latest PII receipt digest",
        children: (
          <span data-testid="pii-receipt-digest-value" className="monospace">
            {typeof run.pii_last_receipt_digest === "string" ? run.pii_last_receipt_digest : "-"}
          </span>
        )
      },
      {
        key: "pii-head",
        label: "Current audit chain head hash",
        children: (
          <span data-testid="pii-audit-head-hash-value" className="monospace">
            {typeof run.pii_audit_head_hash === "string" && run.pii_audit_head_hash.length > 0
              ? run.pii_audit_head_hash
              : "-"}
          </span>
        )
      },
      {
        key: "pii-action",
        label: "PII audit action",
        children: (
          <Button
            type="primary"
            onClick={() => void revealPii()}
            disabled={revealingPii || run.status !== "PASS"}
            loading={revealingPii}
            data-testid="pii-reveal-button"
          >
            {revealingPii ? "Revealing..." : "Reveal PII (audited)"}
          </Button>
        )
      }
    ];
  }, [copyDigest, revealingPii, run]);

  return (
    <div className="page-stack">
      <Space align="center" style={{ justifyContent: "space-between", width: "100%" }} wrap>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/")}>
          Back to runs
        </Button>
        {run?.final_digest ? (
          <Link to={`/artifacts/${run.final_digest}`} className="link-inline">
            Open final artifact page
          </Link>
        ) : (
          <span />
        )}
      </Space>

      {loading ? (
        <Space>
          <Spin />
          <Typography.Text type="secondary">Loading run details</Typography.Text>
        </Space>
      ) : null}
      {error ? <Alert type="error" message={error} showIcon /> : null}

      {run ? (
        <>
          <Card className="card-muted" title={`Run detail · ${run.run_id}`}>
            <Descriptions
              bordered
              column={1}
              items={detailItems}
              labelStyle={{ width: 230 }}
              size="middle"
            />
            {revealError ? (
              <Alert
                type="error"
                message={<span data-testid="pii-reveal-error">{revealError}</span>}
                showIcon
                style={{ marginTop: 12 }}
              />
            ) : null}
          </Card>

          <Card className="card-muted" title="Replay and bundle actions">
            <ReplayActions runId={run.run_id} />
          </Card>

          <Card
            className="card-muted"
            title={
              <Flex align="center" justify="space-between">
                <span>Trace and audit views</span>
                <Typography.Text type="secondary">
                  {run.trace_steps?.length ?? 0} trace steps
                </Typography.Text>
              </Flex>
            }
          >
            <Tabs
              activeKey={activeTab}
              onChange={(key) => setActiveTab(key as RunTab)}
              items={[
                {
                  key: "trace",
                  label: "Step Trace"
                },
                {
                  key: "pii-audit",
                  label: <span data-testid="pii-audit-tab">PII Audit</span>
                }
              ]}
            />

            {activeTab === "trace" ? (
              <StepTraceTable
                runStatus={run.status}
                steps={run.trace_steps ?? []}
                onOpenStep={(step) => {
                  setSelectedStep(step);
                  setStepDialogOpen(true);
                }}
              />
            ) : (
              <PiiAuditPanel run={run} onCopyDigest={copyDigest} />
            )}
          </Card>
        </>
      ) : null}

      <StepDetailDialog
        step={selectedStep}
        open={stepDialogOpen}
        onOpenChange={setStepDialogOpen}
      />
    </div>
  );
}
