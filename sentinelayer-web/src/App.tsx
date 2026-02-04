import { Suspense, lazy } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "@/hooks/AuthProvider";
import { ProtectedRoute } from "@/components/common/ProtectedRoute";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";

const Landing = lazy(() =>
  import("@/pages/Landing").then((module) => ({ default: module.Landing }))
);
const Pricing = lazy(() =>
  import("@/pages/Pricing").then((module) => ({ default: module.Pricing }))
);
const Docs = lazy(() =>
  import("@/pages/Docs").then((module) => ({ default: module.Docs }))
);
const DocsInstall = lazy(() =>
  import("@/pages/DocsInstall").then((module) => ({
    default: module.DocsInstall,
  }))
);
const DocsConfiguration = lazy(() =>
  import("@/pages/DocsConfiguration").then((module) => ({
    default: module.DocsConfiguration,
  }))
);
const Login = lazy(() =>
  import("@/pages/Login").then((module) => ({ default: module.Login }))
);
const LoginCallback = lazy(() =>
  import("@/pages/LoginCallback").then((module) => ({
    default: module.LoginCallback,
  }))
);
const DashboardLayout = lazy(() =>
  import("@/pages/dashboard/Layout").then((module) => ({
    default: module.DashboardLayout,
  }))
);
const Overview = lazy(() =>
  import("@/pages/dashboard/Overview").then((module) => ({
    default: module.Overview,
  }))
);
const Repos = lazy(() =>
  import("@/pages/dashboard/Repos").then((module) => ({
    default: module.Repos,
  }))
);
const RepoDetail = lazy(() =>
  import("@/pages/dashboard/RepoDetail").then((module) => ({
    default: module.RepoDetail,
  }))
);
const Runs = lazy(() =>
  import("@/pages/dashboard/Runs").then((module) => ({
    default: module.Runs,
  }))
);
const RunDetail = lazy(() =>
  import("@/pages/dashboard/RunDetail").then((module) => ({
    default: module.RunDetail,
  }))
);
const Settings = lazy(() =>
  import("@/pages/dashboard/Settings").then((module) => ({
    default: module.Settings,
  }))
);
const Billing = lazy(() =>
  import("@/pages/dashboard/Billing").then((module) => ({
    default: module.Billing,
  }))
);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ErrorBoundary>
          <BrowserRouter>
            <Suspense fallback={<LoadingSpinner fullScreen label="Loading page" />}>
              <Routes>
                <Route path="/" element={<Landing />} />
                <Route path="/pricing" element={<Pricing />} />
                <Route path="/docs" element={<Docs />} />
                <Route path="/docs/install" element={<DocsInstall />} />
                <Route
                  path="/docs/configuration"
                  element={<DocsConfiguration />}
                />
                <Route path="/login" element={<Login />} />
                <Route path="/login/callback" element={<LoginCallback />} />

                <Route
                  path="/dashboard"
                  element={
                    <ProtectedRoute>
                      <DashboardLayout />
                    </ProtectedRoute>
                  }
                >
                  <Route index element={<Overview />} />
                  <Route path="repos" element={<Repos />} />
                  <Route path="repos/:repoId" element={<RepoDetail />} />
                  <Route path="runs" element={<Runs />} />
                  <Route path="runs/:runId" element={<RunDetail />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="billing" element={<Billing />} />
                </Route>
              </Routes>
            </Suspense>
          </BrowserRouter>
        </ErrorBoundary>
      </AuthProvider>
    </QueryClientProvider>
  );
}
