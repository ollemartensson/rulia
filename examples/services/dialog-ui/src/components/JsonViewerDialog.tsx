import { CopyOutlined } from "@ant-design/icons";
import { Alert, Button, Modal, Space, Spin, Typography, message } from "antd";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { getArtifact } from "../api/workflow";
import { DigestPill } from "./DigestPill";

interface JsonViewerDialogProps {
  digest: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function JsonViewerDialog({
  digest,
  open,
  onOpenChange
}: JsonViewerDialogProps): JSX.Element {
  const [artifact, setArtifact] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !digest) {
      return;
    }

    let active = true;
    setLoading(true);
    setError(null);

    getArtifact(digest)
      .then((data) => {
        if (active) {
          setArtifact(data);
        }
      })
      .catch((err: Error) => {
        if (active) {
          setArtifact(null);
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
  }, [digest, open]);

  const jsonText = useMemo(() => {
    if (!artifact) {
      return "";
    }
    return JSON.stringify(artifact, null, 2);
  }, [artifact]);

  async function copyDigest(value: string): Promise<void> {
    await navigator.clipboard.writeText(value);
    message.success("Digest copied");
  }

  return (
    <Modal
      title="Artifact Viewer"
      open={open}
      onCancel={() => onOpenChange(false)}
      width={920}
      footer={[
        <Button key="close" type="primary" onClick={() => onOpenChange(false)}>
          Close
        </Button>
      ]}
      destroyOnHidden
    >
      {digest ? (
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          <div className="key-value-grid">
            <span className="key-label">Digest</span>
            <Space wrap align="center">
              <DigestPill digest={digest} />
              <Button
                icon={<CopyOutlined />}
                onClick={() => void copyDigest(digest)}
                type="text"
              >
                Copy digest
              </Button>
            </Space>
          </div>
          <Link to={`/artifacts/${digest}`} className="link-inline">
            Open full artifact page
          </Link>
        </Space>
      ) : null}

      {loading ? (
        <div style={{ padding: "18px 0" }}>
          <Space>
            <Spin />
            <Typography.Text type="secondary">Loading canonical JSON</Typography.Text>
          </Space>
        </div>
      ) : null}

      {error ? <Alert type="error" message={error} showIcon style={{ marginTop: 12 }} /> : null}

      {!loading && !error && digest ? (
        <pre className="mono-block" style={{ marginTop: 14 }}>
          {jsonText}
        </pre>
      ) : null}
    </Modal>
  );
}
