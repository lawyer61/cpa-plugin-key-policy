import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "./App";
import Lookup from "./pages/Lookup";
import "./styles.css";
import { initThemeSync } from "./store/themeSync";
import { initLangSync } from "./i18n/langSync";

const PUBLIC_LOOKUP_PATH = "/v0/resource/plugins/cpa-key-policy/lookup";
const root = ReactDOM.createRoot(document.getElementById("root")!);
const normalizedPath = window.location.pathname.replace(/\/+$/, "") || "/";

if (normalizedPath === PUBLIC_LOOKUP_PATH) {
  // The public page is deliberately a separate entry path: do not bootstrap a
  // management session, touch browser storage, or mount HashRouter here.
  root.render(
    <React.StrictMode>
      <Lookup />
    </React.StrictMode>,
  );
} else {
  // Mirror the host CPA panel's theme (light/white/dark) onto this iframe's
  // <html> before React mounts, so the first paint already matches the panel
  // and there's no theme flash. No-op / light fallback when opened standalone.
  initThemeSync();

  // Likewise mirror the panel's selected language (zh-CN/zh-TW/en/ru) into our
  // i18n store before React mounts, so the first paint is already in the right
  // language. Falls back to browser default / zh-CN when standalone.
  initLangSync();

  root.render(
    <React.StrictMode>
      <HashRouter>
        <App />
      </HashRouter>
    </React.StrictMode>,
  );
}
