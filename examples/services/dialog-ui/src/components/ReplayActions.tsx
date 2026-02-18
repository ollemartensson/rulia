import { CopyOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Flex, Input, Modal, Space, Typography, message } from "antd";
import { useMemo, useState } from "react";
import { BundleExportResponse, exportBundle } from "../api/workflow";
import { DigestPill } from "./DigestPill";

type ReplayMode = "offline" | "negative";

function toMakeBundle(bundlePath: string): string {
  if (bundlePath.startsWith("/app/")) {
    return bundlePath.slice("/app/".length);
  }
  return bundlePath;
}

interface ReplayActionsProps {
  runId: string;
}

export function ReplayActions({ runId }: ReplayActionsProps): JSX.Element {
  const [exporting, setExporting] = useState(false);
  const [exportData, setExportData] = useState<BundleExportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<ReplayMode | null>(null);
  const [bundleOverride, setBundleOverride] = useState("");

  const bundleValue =
    bundleOverride ||
    (exportData ? toMakeBundle(exportData.bundle_path) : "volumes/bundles/<bundle-id>");

  const command = useMemo(() => {
    if (mode === "negative") {
      return `make replay-negative BUNDLE=${bundleValue}`;
    }
    return `make replay BUNDLE=${bundleValue}`;
  }, [bundleValue, mode]);

  async function copyText(value: string, label: string): Promise<void> {
    await navigator.clipboard.writeText(value);
    message.success(`${label} copied`);
  }

  async function onExport(): Promise<void> {
    try {
      setError(null);
      setExporting(true);
      const result = await exportBundle(runId);
      setExportData(result);
      message.success("Bundle exported");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      message.error("Export failed");
    } finally {
      setExporting(false);
    }
  }

  return (
    <Space direction="vertical" size={14} style={{ width: "100%" }}>
      <Space wrap>
        <Button type="primary" loading={exporting} onClick={() => void onExport()}>
          {exporting ? "Exporting..." : "Export bundle"}
        </Button>
        <Button onClick={() => setMode("offline")}>Replay offline</Button>
        <Button onClick={() => setMode("negative")}>Replay negative (tamper)</Button>
      </Space>

      {exportData ? (
        <Card className="card-subtle">
          <Space direction="vertical" size={8} style={{ width: "100%" }}>
            <Typography.Text type="secondary">
              <strong>Bundle path:</strong> <span className="monospace">{exportData.bundle_path}</span>
            </Typography.Text>
            <DigestPill
              digest={exportData.manifest_digest}
              onCopy={(value) => void copyText(value, "Manifest digest")}
            />
          </Space>
        </Card>
      ) : null}

      {error ? <Alert type="error" message={error} showIcon /> : null}

      <Modal
        open={mode !== null}
        onCancel={() => setMode(null)}
        destroyOnHidden
        width={760}
        title={mode === "negative" ? "Replay negative (tamper)" : "Replay offline"}
        footer={[
          <Button key="close" type="primary" onClick={() => setMode(null)}>
            Close
          </Button>
        ]}
      >
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          <Flex vertical gap={6}>
            <Typography.Text strong>Bundle path used by make</Typography.Text>
            <Input value={bundleValue} onChange={(event) => setBundleOverride(event.target.value)} />
          </Flex>
          <Space align="center" style={{ justifyContent: "space-between", width: "100%" }} wrap>
            <span className="section-heading">Exact command</span>
            <Button icon={<CopyOutlined />} onClick={() => void copyText(command, "Replay command")}>
              Copy
            </Button>
          </Space>
          <pre className="mono-block">{command}</pre>
        </Space>
      </Modal>
    </Space>
  );
}
