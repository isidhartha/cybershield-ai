import { NavLink } from "react-router-dom";
import {
  Shield,
  Search,
  Key,
  Package,
  MessageSquare,
  FileText,
  LayoutDashboard,
  AlertTriangle,
  CheckSquare,
} from "lucide-react";
import clsx from "clsx";

const NAV_ITEMS = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan/code", icon: Search, label: "Code Scan" },
  { to: "/scan/secrets", icon: Key, label: "Secret Detect" },
  { to: "/scan/dependencies", icon: Package, label: "Dep Risk" },
  { to: "/scan/owasp", icon: CheckSquare, label: "OWASP Top 10" },
  { to: "/scan/chat", icon: MessageSquare, label: "AI Assistant" },
  { to: "/scan/report", icon: FileText, label: "Reports" },
];

export function Sidebar() {
  return (
    <aside className="w-56 flex-shrink-0 bg-cyber-surface border-r border-cyber-border flex flex-col">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-cyber-border">
        <Shield className="w-8 h-8 text-cyber-accent" strokeWidth={1.5} />
        <div>
          <p className="font-bold text-cyber-text leading-tight text-sm">CyberShield</p>
          <p className="text-cyber-accent text-xs font-mono">AI Copilot</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              clsx(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all",
                isActive
                  ? "bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20"
                  : "text-cyber-text-dim hover:text-cyber-text hover:bg-cyber-card"
              )
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-cyber-border">
        <div className="flex items-center gap-2 text-xs text-cyber-muted">
          <AlertTriangle className="w-3.5 h-3.5 text-cyber-accent" />
          <span>Authorized use only</span>
        </div>
      </div>
    </aside>
  );
}
