import { ArrowLeftOutlined, CopyOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Flex, Space, Spin, Typography, message } from "antd";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { getArtifact } from "../api/workflow";
import { DigestPill } from "../components/DigestPill";

export function ArtifactPage(): JSX.Element {
  const navigate = useNavigate();
  const params = useParams<{ digest: string }>();
  const digest = useMemo(() => params.digest ?? "", [params.digest]);

  const [artifact, setArtifact] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!digest) {
      setError("digest is required");
      setLoading(false);
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
          setError(err.message);
          setArtifact(null);
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
  }, [digest]);

  const jsonText = useMemo(() => {
    if (!artifact) {
      return "";
    }
    return JSON.stringify(artifact, null, 2);
  }, [artifact]);

  async function copyJson(): Promise<void> {
    await navigator.clipboard.writeText(jsonText);
    message.success("Canonical JSON copied");
  }

  async function copyDigest(value: string): Promise<void> {
    await navigator.clipboard.writeText(value);
    message.success("Digest copied");
  }

  return (
    <div className="page-stack">
      <Space align="center" style={{ justifyContent: "space-between", width: "100%" }} wrap>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)}>
          Back
        </Button>
        <Link to="/" className="link-inline">
          Runs
        </Link>
      </Space>

      <Card className="card-muted">
        <Flex vertical gap={2}>
          <Typography.Title level={4} className="page-title">
            Artifact inspector
          </Typography.Title>
          <Typography.Text className="page-description">
            Canonical JSON view for content-addressed artifacts.
          </Typography.Text>
        </Flex>
      </Card>

      <Card className="card-muted">
        <div className="key-value-grid">
          <span className="key-label">sha256 digest</span>
          <DigestPill digest={digest} onCopy={(value) => void copyDigest(value)} />
        </div>
      </Card>

      <Card className="card-muted">
        <Space align="center" style={{ justifyContent: "space-between", width: "100%" }} wrap>
          <Typography.Text strong>Canonical JSON</Typography.Text>
          <Button icon={<CopyOutlined />} onClick={() => void copyJson()}>
            Copy JSON
          </Button>
        </Space>
        <div style={{ marginTop: 14 }}>
          {loading ? (
            <Space>
              <Spin />
              <Typography.Text type="secondary">Loading artifact</Typography.Text>
            </Space>
          ) : null}
          {error ? <Alert type="error" message={error} showIcon /> : null}
          {!loading && !error ? <pre className="mono-block">{jsonText}</pre> : null}
        </div>
      </Card>
    </div>
  );
}
