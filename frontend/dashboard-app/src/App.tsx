import { Navigate, Route, BrowserRouter, Routes } from "react-router-dom";
import { SessionProvider } from "./auth/session";
import { RequireSession } from "./auth/RequireSession";
import { DataModeProvider } from "./data/DataModeContext";
import { AppShell } from "./components/layout/AppShell";
import { Login } from "./pages/Login/Login";
import { Dashboard } from "./pages/Dashboard/Dashboard";
import { AlertsPage } from "./pages/Alerts/AlertsPage";
import { AlertDetailPage } from "./pages/AlertDetail/AlertDetailPage";
import { FeedbackPage } from "./pages/Feedback/FeedbackPage";
import { RetrainingPage } from "./pages/Retraining/RetrainingPage";
import { AnalyticsPage } from "./pages/Analytics/AnalyticsPage";
import { ShapPage } from "./pages/Shap/ShapPage";

function App() {
  return (
    // DataModeProvider must be outermost: SessionProvider calls useDataProvider() to decide
    // between a real, server-verified session and mock mode's cosmetic one.
    <DataModeProvider>
      <SessionProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              path="/"
              element={
                <RequireSession>
                  <AppShell />
                </RequireSession>
              }
            >
              <Route index element={<Dashboard />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="alerts/:id" element={<AlertDetailPage />} />
              <Route path="analytics" element={<AnalyticsPage />} />
              <Route path="shap" element={<ShapPage />} />
              <Route path="feedback" element={<FeedbackPage />} />
              <Route path="retraining" element={<RetrainingPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </SessionProvider>
    </DataModeProvider>
  );
}

export default App;
