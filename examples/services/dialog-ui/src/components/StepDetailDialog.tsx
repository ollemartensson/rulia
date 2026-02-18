import { Button, Empty, Modal, Table, Tabs, message } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useMemo, useState } from "react";
import { WorkflowTraceStep } from "../api/workflow";
import { DigestPill } from "./DigestPill";
import { JsonViewerDialog } from "./JsonViewerDialog";

const tabs = ["inputs", "outputs", "obligations", "receipts"] as const;
type StepTab = (typeof tabs)[number];

interface StepDetailDialogProps {
  step: WorkflowTraceStep | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function digestsForTab(step: WorkflowTraceStep, tab: StepTab): string[] {
  if (tab === "inputs") {
    return step.input_digests ?? [];
  }
  if (tab === "outputs") {
    return step.output_digests ?? [];
  }
  if (tab === "obligations") {
    return step.obligation_digests ?? [];
  }
  return step.receipt_digests ?? [];
}

export function StepDetailDialog({
  step,
  open,
  onOpenChange
}: StepDetailDialogProps): JSX.Element {
  const [activeTab, setActiveTab] = useState<StepTab>("inputs");
  const [artifactDigest, setArtifactDigest] = useState<string | null>(null);
  const [artifactOpen, setArtifactOpen] = useState(false);

  const currentDigests = useMemo(() => {
    if (!step) {
      return [];
    }

    return digestsForTab(step, activeTab).map((digest, index) => ({
      key: `${digest}-${index}`,
      digest
    }));
  }, [activeTab, step]);

  const columns = useMemo<ColumnsType<{ key: string; digest: string }>>(
    () => [
      {
        title: "Digest",
        dataIndex: "digest",
        render: (digest: string) => (
          <DigestPill
            digest={digest}
            onCopy={(value) => void copyDigest(value)}
            onOpen={openArtifact}
          />
        )
      }
    ],
    []
  );

  async function copyDigest(digest: string): Promise<void> {
    await navigator.clipboard.writeText(digest);
    message.success("Digest copied");
  }

  function openArtifact(digest: string): void {
    setArtifactDigest(digest);
    setArtifactOpen(true);
  }

  return (
    <>
      <Modal
        open={open}
        onCancel={() => onOpenChange(false)}
        width={760}
        title={`Step details ${step ? `${step.step_id} • ${step.step_type}` : ""}`}
        destroyOnHidden
        footer={[
          <Button key="close" type="primary" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        ]}
      >
        <Tabs
          activeKey={activeTab}
          onChange={(key) => setActiveTab(key as StepTab)}
          items={tabs.map((tab) => ({
            key: tab,
            label: tab.charAt(0).toUpperCase() + tab.slice(1)
          }))}
        />
        {currentDigests.length === 0 ? (
          <Empty description="No digests for this tab." image={Empty.PRESENTED_IMAGE_SIMPLE} />
        ) : (
          <Table
            className="trace-table"
            columns={columns}
            dataSource={currentDigests}
            pagination={false}
            size="small"
          />
        )}
      </Modal>
      <JsonViewerDialog
        digest={artifactDigest}
        open={artifactOpen}
        onOpenChange={setArtifactOpen}
      />
    </>
  );
}
