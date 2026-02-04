import { Link, NavLink } from "react-router-dom";
import {
  FolderGit2,
  History,
  LayoutDashboard,
  Settings,
  Shield,
  LogOut,
} from "lucide-react";
import type { User } from "@/types/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/useAuth";

const navItems = [
  { icon: LayoutDashboard, label: "Overview", href: "/dashboard" },
  { icon: FolderGit2, label: "Repositories", href: "/dashboard/repos" },
  { icon: History, label: "Run History", href: "/dashboard/runs" },
  { icon: Settings, label: "Settings", href: "/dashboard/settings" },
];

export function Sidebar({ user }: { user: User | null }) {
  const { logout } = useAuth();

  return (
    <aside className="hidden min-h-screen w-72 flex-col border-r border-border/60 bg-card/60 p-6 lg:flex">
      <Link to="/" className="flex items-center gap-2">
        <Shield className="h-8 w-8 text-primary" />
        <span className="font-display text-xl font-semibold">Sentinelayer</span>
      </Link>

      <nav className="mt-10 flex flex-1 flex-col gap-2">
        {navItems.map((item) => (
          <NavLink
            key={item.href}
            to={item.href}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-2xl px-4 py-3 text-sm font-medium transition",
                isActive
                  ? "bg-primary text-primary-foreground shadow-soft"
                  : "text-muted-foreground hover:bg-muted/70 hover:text-foreground"
              )
            }
          >
            <item.icon className="h-5 w-5" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="rounded-2xl border border-border/60 bg-background p-4">
        {user ? (
          <div className="flex items-center gap-3">
            <img
              src={user.avatar_url}
              alt={user.github_username}
              className="h-10 w-10 rounded-full"
            />
            <div className="flex-1">
              <p className="text-sm font-semibold">{user.github_username}</p>
              <p className="text-xs text-muted-foreground">{user.email}</p>
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Signed out</p>
        )}

        <Button
          variant="ghost"
          size="sm"
          className="mt-4 w-full justify-start"
          onClick={logout}
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </Button>
      </div>
    </aside>
  );
}
