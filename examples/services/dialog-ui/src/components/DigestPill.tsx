import { CopyOutlined, ExportOutlined } from "@ant-design/icons";
import { Button, Space, Tag, Tooltip } from "antd";

interface DigestPillProps {
  digest: string;
  onCopy?: (digest: string) => void;
  onOpen?: (digest: string) => void;
}

export function DigestPill({ digest, onCopy, onOpen }: DigestPillProps): JSX.Element {
  const short =
    digest.length > 24 ? `${digest.slice(0, 12)}…${digest.slice(-8)}` : digest;

  return (
    <Space size={4} wrap>
      <Tooltip title={digest}>
        <Tag className="digest-pill-tag monospace" bordered>
          {short}
        </Tag>
      </Tooltip>
      <Button
        aria-label="Copy digest"
        type="text"
        icon={<CopyOutlined />}
        size="small"
        onClick={() => onCopy?.(digest)}
      />
      {onOpen ? (
        <Button
          aria-label="Open digest"
          type="text"
          icon={<ExportOutlined />}
          size="small"
          onClick={() => onOpen(digest)}
        />
      ) : null}
    </Space>
  );
}
