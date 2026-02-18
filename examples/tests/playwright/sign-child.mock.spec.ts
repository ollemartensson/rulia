import { test } from "@playwright/test";
import { runMockSigningFlow, runOptionalRealModeFlow } from "./signing-flow.js";

test("child signing page completes mock BankID + workflow receipt flow", async ({ page }) => {
  await runMockSigningFlow(page, "child");
});

test("child signing optional real BankID flow", async ({ page }) => {
  test.skip(
    process.env.PW_REAL_BANKID_E2E !== "1" || process.env.BANKID_MODE !== "real",
    "Set BANKID_MODE=real and PW_REAL_BANKID_E2E=1 to enable real-mode Playwright flow."
  );

  await runOptionalRealModeFlow(page, "child");
});
