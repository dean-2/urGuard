import type { ReactNode } from 'react';
import { NavLink } from 'react-router';
import { Badge } from '../components/Badge.tsx';
import type { SystemHealth } from '../api/types.ts';
import type { SubscriptionStatus } from '../hooks/useSubscription.ts';

interface AppShellProps {
  readonly mode: 'mock' | 'live';
  readonly health: SystemHealth | null;
  readonly streamStatus: SubscriptionStatus;
  readonly children: ReactNode;
}

function nodeTone(status: string): 'success' | 'warning' | 'danger' {
  if (status === 'HEALTHY') return 'success';
  if (status === 'DEGRADED') return 'warning';
  return 'danger';
}

/**
 * Primary console layout: left sidebar for the 4 Track 4 workflows and top header
 * displaying control plane and node-a/b/c health.
 */
export function AppShell({ mode, health, streamStatus, children }: AppShellProps) {
  return (
    <div className="console-layout">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <span className="brand-title">urGuard</span>
          <span className="brand-subtitle">PQC Zero-Trust Console</span>
        </div>

        <nav className="sidebar-nav" aria-label="Console routes">
          <NavLink
            to="/"
            end
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Messaging
          </NavLink>
          <NavLink
            to="/governance"
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Key Governance
          </NavLink>
          <NavLink
            to="/audit"
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Audit Log
          </NavLink>
          <NavLink
            to="/detection"
            className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
          >
            Detection
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <Badge tone="info" testId="client-mode">
            mode: {mode}
          </Badge>
          <Badge tone={streamStatus === 'connected' ? 'success' : 'warning'} testId="stream-status">
            stream: {streamStatus}
          </Badge>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar" aria-label="Cluster health header">
          <div className="health-strip">
            <Badge
              tone={health?.controlPlaneReady ? 'success' : 'danger'}
              testId="health-controlplane"
            >
              controlplane: {health?.controlPlaneReady ? 'READY' : 'UNAVAILABLE'}
            </Badge>
            {(health?.nodes ?? []).map((node) => (
              <Badge
                key={node.nodeId}
                tone={nodeTone(node.status)}
                testId={`health-${node.nodeId}`}
              >
                {node.nodeId}: {node.status} (ep {String(node.activeKeyEpoch)} / crl{' '}
                {String(node.crlEpoch)})
              </Badge>
            ))}
          </div>
          <div className="status-strip">
            <Badge tone="neutral" testId="active-epoch">
              epoch: {health ? String(health.rotation.currentEpoch) : '--'}
            </Badge>
          </div>
        </header>

        <main className="main-content">{children}</main>
      </div>
    </div>
  );
}
