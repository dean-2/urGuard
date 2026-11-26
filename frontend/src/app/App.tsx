import { useCallback } from 'react';
import { Route, Routes } from 'react-router';
import { urGuardClient, type UrGuardClient } from '../api/client.ts';
import type { SystemHealth } from '../api/types.ts';
import { useSubscription } from '../hooks/useSubscription.ts';
import { AuditView } from '../views/audit/AuditView.tsx';
import { DetectionView } from '../views/detection/DetectionView.tsx';
import { GovernanceView } from '../views/governance/GovernanceView.tsx';
import { MessagingView } from '../views/messaging/MessagingView.tsx';
import { AppShell } from './AppShell.tsx';

interface AppProps {
  readonly client?: UrGuardClient;
}

/** Root application router wiring all 4 operator console views. */
export function App({ client = urGuardClient }: AppProps) {
  const subscribeHealth = useCallback(
    (handlers: Parameters<UrGuardClient['subscribeSystemHealth']>[0]) =>
      client.subscribeSystemHealth(handlers),
    [client],
  );

  const { data: health, status: streamStatus } = useSubscription<SystemHealth>(subscribeHealth, [
    client,
  ]);

  return (
    <AppShell mode={client.mode} health={health} streamStatus={streamStatus}>
      <Routes>
        <Route path="/" element={<MessagingView client={client} />} />
        <Route path="/governance" element={<GovernanceView client={client} />} />
        <Route path="/audit" element={<AuditView client={client} />} />
        <Route path="/detection" element={<DetectionView client={client} />} />
      </Routes>
    </AppShell>
  );
}
