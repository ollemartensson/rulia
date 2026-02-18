import { Button, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { WorkflowRun, displayCreated, stepsVerified } from "../api/workflow";
import { DigestPill } from "./DigestPill";

interface RunListProps {
  runs: WorkflowRun[];
  onCopyDigest: (digest: string) => void;
  onOpenDigest: (digest: string) => void;
}

export function RunList({ runs, onCopyDigest, onOpenDigest }: RunListProps): JSX.Element {
  const navigate = useNavigate();

  const columns = useMemo<ColumnsType<WorkflowRun>>(
    () => [
      {
        title: "Run ID",
        dataIndex: "run_id",
        key: "run_id",
        width: 240,
        render: (value: string) => <Typography.Text className="monospace">{value}</Typography.Text>
      },
      {
        title: "Status",
        dataIndex: "status",
        key: "status",
        width: 110,
        render: (value: string) => (
          <Tag color={value === "PASS" ? "success" : "warning"}>{value}</Tag>
        )
      },
      {
        title: "Final digest",
        dataIndex: "final_digest",
        key: "final_digest",
        width: 280,
        render: (value: string | undefined) =>
          value ? (
            <DigestPill digest={value} onCopy={onCopyDigest} onOpen={onOpenDigest} />
          ) : (
            "-"
          )
      },
      {
        title: "Steps verified",
        key: "steps_verified",
        width: 140,
        render: (_, record) => stepsVerified(record)
      },
      {
        title: "Created / order",
        key: "created_order",
        width: 220,
        render: (_, record, index) => (
          <Typography.Text type="secondary">{displayCreated(record, index + 1)}</Typography.Text>
        )
      },
      {
        title: "Actions",
        key: "actions",
        width: 130,
        render: (_, record) => (
          <Button
            type="primary"
            size="small"
            onClick={() => navigate(`/runs/${encodeURIComponent(record.run_id)}`)}
          >
            Open run
          </Button>
        )
      }
    ],
    [navigate, onCopyDigest, onOpenDigest]
  );

  return (
    <Table
      className="runs-table"
      columns={columns}
      dataSource={runs}
      rowKey={(record) => record.run_id}
      pagination={false}
      size="middle"
      scroll={{ x: 1050 }}
    />
  );
}
