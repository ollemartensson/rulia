import { Button, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useMemo } from "react";
import { digestCount, deriveStepResult, WorkflowTraceStep } from "../api/workflow";

interface StepTraceTableProps {
  runStatus: string;
  steps: WorkflowTraceStep[];
  onOpenStep: (step: WorkflowTraceStep) => void;
}

interface StepRow extends WorkflowTraceStep {
  key: string;
  index: number;
}

function tagColor(result: "ok" | "pending" | "fail"): string {
  if (result === "ok") {
    return "success";
  }
  if (result === "fail") {
    return "error";
  }
  return "gold";
}

export function StepTraceTable({
  runStatus,
  steps,
  onOpenStep
}: StepTraceTableProps): JSX.Element {
  const rows = useMemo<StepRow[]>(
    () =>
      steps.map((step, index) => ({
        ...step,
        index,
        key: `${step.step_id}-${step.step_type}-${index}`
      })),
    [steps]
  );

  const columns = useMemo<ColumnsType<StepRow>>(
    () => [
      {
        title: "Step",
        dataIndex: "step_id",
        key: "step_id",
        width: 120,
        render: (value: string) => <Typography.Text strong>{value}</Typography.Text>
      },
      {
        title: "Type",
        dataIndex: "step_type",
        key: "step_type",
        width: 230,
        render: (value: string) => <Typography.Text className="monospace">{value}</Typography.Text>
      },
      {
        title: "Result",
        key: "result",
        width: 110,
        render: (_, row) => {
          const result = deriveStepResult(runStatus, row, row.index, rows.length);
          return <Tag color={tagColor(result)}>{result.toUpperCase()}</Tag>;
        }
      },
      {
        title: "#Inputs",
        key: "inputs",
        width: 90,
        render: (_, row) => digestCount(row.input_digests)
      },
      {
        title: "#Outputs",
        key: "outputs",
        width: 100,
        render: (_, row) => digestCount(row.output_digests)
      },
      {
        title: "#Obligations",
        key: "obligations",
        width: 120,
        render: (_, row) => digestCount(row.obligation_digests)
      },
      {
        title: "#Receipts",
        key: "receipts",
        width: 100,
        render: (_, row) => digestCount(row.receipt_digests)
      },
      {
        title: "Actions",
        key: "actions",
        width: 110,
        render: (_, row) => (
          <Button size="small" type="primary" onClick={() => onOpenStep(row)}>
            Inspect
          </Button>
        )
      }
    ],
    [onOpenStep, rows.length, runStatus]
  );

  return (
    <Table
      className="trace-table"
      columns={columns}
      dataSource={rows}
      pagination={false}
      size="middle"
      scroll={{ x: 1060 }}
      rowKey="key"
    />
  );
}
