import { Alert, Card, Flex, Input, Space, Spin, Typography, message } from "antd";
import { useEffect, useMemo, useState } from "react";
import { getRuns, WorkflowRun } from "../api/workflow";
import { JsonViewerDialog } from "../components/JsonViewerDialog";
import { RunList } from "../components/RunList";

export function RunsPage(): JSX.Element {
  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [artifactDigest, setArtifactDigest] = useState<string | null>(null);
  const [artifactOpen, setArtifactOpen] = useState(false);

  useEffect(() => {
    let active = true;

    getRuns()
      .then((data) => {
        if (active) {
          setRuns(data);
        }
      })
      .catch((err: Error) => {
        if (active) {
          setError(err.message);
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  const filtered = useMemo(() => {
    const normalized = filter.trim().toLowerCase();
    if (!normalized) {
      return runs;
    }
    return runs.filter((run) => run.run_id.toLowerCase().includes(normalized));
  }, [filter, runs]);

  async function copyDigest(digest: string): Promise<void> {
    await navigator.clipboard.writeText(digest);
    message.success("Digest copied");
  }

  return (
    <div className="page-stack">
      <Card className="card-muted">
        <div className="page-toolbar">
          <Flex vertical gap={2}>
            <Typography.Title level={4} className="page-title">
              Workflow runs
            </Typography.Title>
            <Typography.Text className="page-description">
              Search and inspect deterministic run traces.
            </Typography.Text>
          </Flex>
          <Input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Filter by run_id (run-...)"
            style={{ maxWidth: 380 }}
            allowClear
          />
        </div>
      </Card>

      {loading ? (
        <Space>
          <Spin />
          <Typography.Text type="secondary">Loading workflow runs</Typography.Text>
        </Space>
      ) : null}
      {error ? <Alert type="error" message={error} showIcon /> : null}

      {!loading && !error ? (
        <Card className="card-muted" title={`Run records (${filtered.length})`}>
          <RunList
            runs={filtered}
            onCopyDigest={(digest) => void copyDigest(digest)}
            onOpenDigest={(digest) => {
              setArtifactDigest(digest);
              setArtifactOpen(true);
            }}
          />
        </Card>
      ) : null}

      <JsonViewerDialog
        digest={artifactDigest}
        open={artifactOpen}
        onOpenChange={setArtifactOpen}
      />
    </div>
  );
}
