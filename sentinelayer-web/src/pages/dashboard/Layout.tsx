import { Outlet, Link } from "react-router-dom";
import { Shield, LogOut } from "lucide-react";
import { Sidebar } from "@/components/layout/Sidebar";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";

export function DashboardLayout() {
  const { user, logout } = useAuth();

  return (
    <div className="min-h-screen bg-background lg:flex">
      <Sidebar user={user} />

      <div className="flex-1">
        <div className="flex items-center justify-between border-b border-border/60 bg-background/80 px-6 py-4 lg:hidden">
          <Link to="/" className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-display text-lg font-semibold">Sentinelayer</span>
          </Link>
          <Button variant="ghost" size="sm" onClick={logout}>
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>

        <main className="p-6 md:p-10">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
