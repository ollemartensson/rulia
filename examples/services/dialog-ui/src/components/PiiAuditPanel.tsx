import { Alert, Badge, Button, Card, Modal, Space, Spin, Table, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useEffect, useMemo, useState } from "react";
import {
  getLedgerChain,
  LedgerChainEvent,
  WorkflowPiiAccess,
  WorkflowRun
} from "../api/workflow";
import { DigestPill } from "./DigestPill";
import { JsonViewerDialog } from "./JsonViewerDialog";

const HEX64_RE = /^[0-9a-f]{64}$/;
const GENESIS_PREV_HASH = "0".repeat(64);

interface PiiAuditPanelProps {
  run: WorkflowRun;
  onCopyDigest: (digest: string) => Promise<void>;
}

interface PiiAuditRow {
  key: string;
  receiptDigest: string;
  ledgerReceiptDigest: string;
  decision: string;
  actor: string;
  purpose: string;
  fields: string[];
  piiRef: string;
  auditEventHash: string;
  auditHeadHash: string;
}

interface VerificationResult {
  verified: boolean;
  detail: string;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeHash(value: unknown): string {
  const normalized = asString(value).toLowerCase();
  return HEX64_RE.test(normalized) ? normalized : "";
}

function toPiiRows(run: WorkflowRun): PiiAuditRow[] {
  const accesses = Array.isArray(run.pii_accesses) ? run.pii_accesses : [];

  return accesses.map((access: WorkflowPiiAccess, index) => {
    const receiptDigest = asString(access.receipt_digest);
    const ledgerReceiptDigest = asString(access.ledger_receipt_digest);
    const actorId = asString(access.actor_id);
    const actorType = asString(access.actor_type);
    const actor = [actorType, actorId].filter((value) => value.length > 0).join(":");
    const rawFields = Array.isArray(access.fields) ? access.fields : [];
    const fields = rawFields
      .map((field) => asString(field))
      .filter((field) => field.length > 0);

    return {
      key: `${receiptDigest || "none"}-${index}`,
      receiptDigest,
      ledgerReceiptDigest,
      decision: asString(access.decision).toUpperCase() || "ALLOW",
      actor: actor || "-",
      purpose: asString(access.purpose) || "-",
      fields,
      piiRef: asString(access.pii_ref) || asString(access.subject_id) || "-",
      auditEventHash: normalizeHash(access.audit_event_hash),
      auditHeadHash: normalizeHash(access.audit_head_hash) || normalizeHash(access.head_hash)
    };
  });
}

function verifyLedgerChain(
  headHash: string,
  events: LedgerChainEvent[],
  piiRows: PiiAuditRow[]
): VerificationResult {
  if (!headHash) {
    return {
      verified: false,
      detail: "missing run audit head hash"
    };
  }

  if (events.length === 0) {
    return {
      verified: false,
      detail: "ledger chain is empty"
    };
  }

  let expectedSequence = -1;
  let previousEventHash = "";
  const chainHashes = new Set<string>();

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const sequence = typeof event.sequence === "number" ? event.sequence : Number.NaN;
    const eventHash = normalizeHash(event.event_hash);
    const prevHash = normalizeHash(event.prev_hash);

    if (!Number.isInteger(sequence) || sequence <= 0) {
      return {
        verified: false,
        detail: "ledger chain contains invalid sequence values"
      };
    }

    if (!eventHash || !prevHash) {
      return {
        verified: false,
        detail: "ledger chain contains malformed hashes"
      };
    }

    if (index === 0) {
      expectedSequence = sequence;
      if (prevHash !== GENESIS_PREV_HASH) {
        return {
          verified: false,
          detail: "ledger chain genesis hash mismatch"
        };
      }
    }

    if (sequence !== expectedSequence) {
      return {
        verified: false,
        detail: "ledger chain sequence continuity failed"
      };
    }

    if (index > 0 && prevHash !== previousEventHash) {
      return {
        verified: false,
        detail: "ledger chain prev_hash linkage failed"
      };
    }

    expectedSequence += 1;
    previousEventHash = eventHash;
    chainHashes.add(eventHash);
  }

  if (previousEventHash !== headHash) {
    return {
      verified: false,
      detail: "run head hash does not match ledger chain head"
    };
  }

  for (const row of piiRows) {
    if (!row.auditEventHash) {
      return {
        verified: false,
        detail: "PII access row missing audit_event_hash"
      };
    }

    if (!chainHashes.has(row.auditEventHash)) {
      return {
        verified: false,
        detail: "PII access audit_event_hash missing from ledger chain"
      };
    }
  }

  return {
    verified: true,
    detail: "continuity and run-linked PII audit events verified"
  };
}

function stringifyJson(obj: unknown): string {
  return JSON.stringify(obj, null, 2);
}

export function PiiAuditPanel({ run, onCopyDigest }: PiiAuditPanelProps): JSX.Element {
  const [artifactDigest, setArtifactDigest] = useState<string | null>(null);
  const [artifactOpen, setArtifactOpen] = useState(false);
  const [ledgerDialogOpen, setLedgerDialogOpen] = useState(false);
  const [focusedHash, setFocusedHash] = useState<string>("");
  const [ledgerEvents, setLedgerEvents] = useState<LedgerChainEvent[]>([]);
  const [ledgerJsonl, setLedgerJsonl] = useState<string>("");
  const [ledgerLoading, setLedgerLoading] = useState(false);
  const [ledgerError, setLedgerError] = useState<string | null>(null);

  const piiRows = useMemo(() => toPiiRows(run), [run]);
  const headHash = useMemo(
    () => normalizeHash(run.pii_audit_head_hash) || normalizeHash(run.audit_chain_head_hash),
    [run]
  );

  useEffect(() => {
    if (!headHash) {
      setLedgerEvents([]);
      setLedgerJsonl("");
      setLedgerError(null);
      setLedgerLoading(false);
      return;
    }

    let active = true;
    setLedgerLoading(true);
    setLedgerError(null);

    getLedgerChain(headHash)
      .then((chain) => {
        if (!active) {
          return;
        }
        setLedgerEvents(chain.events);
        setLedgerJsonl(chain.raw_jsonl);
      })
      .catch((err: Error) => {
        if (!active) {
          return;
        }
        setLedgerEvents([]);
        setLedgerJsonl("");
        setLedgerError(err.message);
      })
      .finally(() => {
        if (active) {
          setLedgerLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [headHash]);

  const selectedLedgerEvent = useMemo(() => {
    if (!focusedHash) {
      return null;
    }
    return (
      ledgerEvents.find((event) => normalizeHash(event.event_hash) === normalizeHash(focusedHash)) ??
      null
    );
  }, [focusedHash, ledgerEvents]);

  const verification = useMemo(() => {
    if (ledgerLoading) {
      return {
        verified: false,
        detail: "verifying chain..."
      };
    }

    if (ledgerError) {
      return {
        verified: false,
        detail: ledgerError
      };
    }

    return verifyLedgerChain(headHash, ledgerEvents, piiRows);
  }, [headHash, ledgerError, ledgerEvents, ledgerLoading, piiRows]);

  const columns = useMemo<ColumnsType<PiiAuditRow>>(
    () => [
      {
        title: "Receipt digest",
        dataIndex: "receiptDigest",
        width: 208,
        render: (value: string) => (
          <span data-testid="pii-audit-receipt-cell">
            {value ? (
              <DigestPill
                digest={value}
                onCopy={(digest) => void onCopyDigest(digest)}
                onOpen={(digest) => {
                  setArtifactDigest(digest);
                  setArtifactOpen(true);
                }}
              />
            ) : (
              "-"
            )}
          </span>
        )
      },
      {
        title: "Decision",
        dataIndex: "decision",
        width: 110,
        render: (value: string) => (
          <span data-testid="pii-audit-decision-cell">
            <Badge
              status={value === "ALLOW" ? "success" : "error"}
              text={<span className="status-badge">{value}</span>}
            />
          </span>
        )
      },
      {
        title: "Actor",
        dataIndex: "actor",
        width: 180
      },
      {
        title: "Purpose",
        dataIndex: "purpose",
        width: 180
      },
      {
        title: "Fields",
        dataIndex: "fields",
        width: 200,
        render: (value: string[]) => value.join(", ") || "-"
      },
      {
        title: "PII ref",
        dataIndex: "piiRef",
        width: 180,
        render: (value: string) => <span className="monospace">{value}</span>
      },
      {
        title: "Audit event hash",
        dataIndex: "auditEventHash",
        width: 208,
        render: (value: string) => (
          <span data-testid="pii-audit-event-hash-cell">
            {value ? (
              <DigestPill
                digest={value}
                onCopy={(digest) => void onCopyDigest(digest)}
                onOpen={(digest) => {
                  setFocusedHash(normalizeHash(digest));
                  setLedgerDialogOpen(true);
                }}
              />
            ) : (
              "-"
            )}
          </span>
        )
      },
      {
        title: "Audit head hash",
        dataIndex: "auditHeadHash",
        width: 208,
        render: (value: string) =>
          value ? (
            <DigestPill
              digest={value}
              onCopy={(digest) => void onCopyDigest(digest)}
              onOpen={(digest) => {
                setFocusedHash(normalizeHash(digest));
                setLedgerDialogOpen(true);
              }}
            />
          ) : (
            "-"
          )
      }
    ],
    [onCopyDigest]
  );

  return (
    <Space direction="vertical" size={16} className="full-width">
      <Card className="card-subtle">
        <Space direction="vertical" size={10} className="full-width">
          <div className="key-value-grid">
            <span className="key-label">Chain status</span>
            <span className="key-value" data-testid="pii-audit-chain-status-value">
              <Badge
                status={verification.verified ? "success" : "error"}
                text={verification.verified ? "VERIFIED" : "UNVERIFIED"}
              />
              <Typography.Text type="secondary"> {verification.detail}</Typography.Text>
            </span>
          </div>
          <div className="key-value-grid">
            <span className="key-label">Audit head hash</span>
            <span className="key-value" data-testid="pii-audit-chain-head-value">
              {headHash ? (
                <DigestPill
                  digest={headHash}
                  onCopy={(digest) => void onCopyDigest(digest)}
                  onOpen={(hash) => {
                    setFocusedHash(normalizeHash(hash));
                    setLedgerDialogOpen(true);
                  }}
                />
              ) : (
                "-"
              )}
            </span>
          </div>
          <div className="key-value-grid">
            <span className="key-label">Ledger events loaded</span>
            <span className="key-value" data-testid="pii-audit-ledger-count-value">
              {ledgerLoading ? "loading..." : ledgerEvents.length}
            </span>
          </div>
          <Button
            onClick={() => setLedgerDialogOpen(true)}
            data-testid="pii-audit-view-chain-button"
            style={{ width: "fit-content" }}
          >
            View ledger chain
          </Button>
        </Space>
      </Card>

      <Card className="card-muted" styles={{ body: { padding: 0 } }}>
        <div data-testid="pii-audit-table">
          <Table<PiiAuditRow>
            className="ledger-table"
            columns={columns}
            dataSource={piiRows}
            pagination={false}
            scroll={{ x: 1300 }}
            locale={{ emptyText: <span className="empty-block">No audited PII access events for this run.</span> }}
            onRow={() => ({ "data-testid": "pii-audit-row" })}
          />
        </div>
      </Card>

      <Modal
        open={ledgerDialogOpen}
        onCancel={() => setLedgerDialogOpen(false)}
        width={980}
        title={<span data-testid="pii-ledger-chain-dialog-title">Ledger Chain Viewer</span>}
        footer={
          <Button type="primary" onClick={() => setLedgerDialogOpen(false)}>
            Close
          </Button>
        }
        destroyOnHidden
      >
        <div className="modal-content-stack">
          {ledgerLoading ? (
            <Space>
              <Spin />
              <Typography.Text type="secondary">Loading ledger chain</Typography.Text>
            </Space>
          ) : null}
          {ledgerError ? <Alert type="error" showIcon message={ledgerError} /> : null}
          {!ledgerLoading && !ledgerError ? (
            <>
              <Typography.Text type="secondary">
                Showing {ledgerEvents.length} event(s) up to head hash <strong>{headHash || "-"}</strong>
              </Typography.Text>
              {selectedLedgerEvent ? (
                <Card className="card-subtle" size="small" title={`Selected event (${focusedHash})`}>
                  <pre className="mono-block">{stringifyJson(selectedLedgerEvent)}</pre>
                </Card>
              ) : null}
              <Space direction="vertical" size={6} className="full-width">
                <Typography.Text strong>JSONL preview</Typography.Text>
                <pre className="mono-block" data-testid="pii-ledger-chain-jsonl">
                  {ledgerJsonl || "(empty)"}
                </pre>
              </Space>
            </>
          ) : null}
        </div>
      </Modal>

      <JsonViewerDialog
        digest={artifactDigest}
        open={artifactOpen}
        onOpenChange={setArtifactOpen}
      />
    </Space>
  );
}
