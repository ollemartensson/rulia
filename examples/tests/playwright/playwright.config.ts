import { defineConfig } from "@playwright/test";

const realModeEnabled = process.env.BANKID_MODE === "real";

export default defineConfig({
  testDir: ".",
  testMatch: ["**/*.spec.ts"],
  fullyParallel: true,
  timeout: realModeEnabled ? 150_000 : 60_000,
  outputDir: "artifacts",
  expect: {
    timeout: 20_000
  },
  retries: 1,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:8080",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure"
  }
});
