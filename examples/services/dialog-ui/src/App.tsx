import { HomeOutlined, ReloadOutlined } from "@ant-design/icons";
import {
  App as AntApp,
  Badge,
  Button,
  Card,
  ConfigProvider,
  Flex,
  Layout,
  Space,
  Typography,
  type ThemeConfig
} from "antd";
import { Link, Navigate, Route, Routes } from "react-router-dom";
import { ArtifactPage } from "./pages/ArtifactPage";
import { PublicSigningPage } from "./pages/PublicSigningPage";
import { RunDetailPage } from "./pages/RunDetailPage";
import { RunsPage } from "./pages/RunsPage";

const appTheme: ThemeConfig = {
  token: {
    colorPrimary: "#165dce",
    colorInfo: "#165dce",
    colorText: "#13233f",
    colorTextSecondary: "#4d6082",
    colorBgContainer: "#ffffff",
    colorBorder: "#d8e4f4",
    colorSuccess: "#1f9d63",
    colorWarning: "#cf8f12",
    colorError: "#cb2d2d",
    borderRadius: 12,
    borderRadiusLG: 16,
    borderRadiusSM: 10,
    fontFamily: "'Manrope', 'Avenir Next', 'Segoe UI', sans-serif",
    fontFamilyCode: "'JetBrains Mono', 'SFMono-Regular', Menlo, monospace"
  },
  components: {
    Card: {
      bodyPadding: 20,
      headerFontSize: 16
    },
    Table: {
      headerBg: "#f4f8ff",
      headerColor: "#1d3460",
      borderColor: "#d8e2f0",
      rowHoverBg: "#f7faff"
    },
    Tabs: {
      inkBarColor: "#0a63e5"
    },
    Modal: {
      titleFontSize: 18
    },
    Button: {
      controlHeight: 36,
      fontWeight: 600
    }
  }
};

export default function App(): JSX.Element {
  return (
    <ConfigProvider theme={appTheme}>
      <AntApp>
        <Layout className="app-shell">
          <div className="app-container">
            <Card className="app-header-card" variant="borderless">
              <Flex align="center" justify="space-between" gap={16} wrap>
                <div className="app-title-block">
                  <Space size={8} align="center">
                    <Badge status="processing" />
                    <Typography.Text type="secondary">Deterministic workflow console</Typography.Text>
                  </Space>
                  <Typography.Title level={2} className="app-title">
                    Rulia Workflow Dialogs
                  </Typography.Title>
                  <Typography.Text type="secondary">
                    Read-only Ant Design lens for deterministic workflow traces and artifacts.
                  </Typography.Text>
                </div>
                <Space wrap>
                  <Link to="/">
                    <Button icon={<HomeOutlined />}>Runs</Button>
                  </Link>
                  <Button icon={<ReloadOutlined />} onClick={() => window.location.reload()}>
                    Refresh
                  </Button>
                </Space>
              </Flex>
            </Card>

            <Layout.Content>
              <Routes>
                <Route path="/" element={<RunsPage />} />
                <Route path="/runs/:runId" element={<RunDetailPage />} />
                <Route path="/artifacts/:digest" element={<ArtifactPage />} />
                <Route path="/sign/parent/:token" element={<PublicSigningPage role="parent" />} />
                <Route path="/sign/child/:token" element={<PublicSigningPage role="child" />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout.Content>
          </div>
        </Layout>
      </AntApp>
    </ConfigProvider>
  );
}
