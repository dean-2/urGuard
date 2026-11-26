import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { createMockClient } from '../../mocks/mockClient.ts';
import { DetectionView } from './DetectionView.tsx';

describe('DetectionView', () => {
  it('renders KPI metrics, React Flow identity-service graph, and lateral movement alert drawer', async () => {
    const client = createMockClient();
    render(<DetectionView client={client} />);

    await waitFor(() => {
      expect(screen.getByTestId('kpi-precision')).toHaveTextContent('0.97');
      expect(screen.getByTestId('kpi-recall')).toHaveTextContent('0.95');
      expect(screen.getByTestId('kpi-f1')).toHaveTextContent('0.96');
      expect(screen.getByTestId('kpi-alert-latency')).toHaveTextContent('145 ms');
      expect(screen.getByTestId('kpi-false-alerts')).toHaveTextContent('0.8');
    });

    await waitFor(() => {
      expect(screen.getByTestId('access-graph-canvas')).toBeInTheDocument();
      expect(screen.getByText('edge-gateway (T1)')).toBeInTheDocument();
      expect(screen.getByText('secrets-vault (T3)')).toBeInTheDocument();
    });

    const drawer = screen.getByTestId('alert-drawer');
    expect(drawer).toHaveTextContent('svc-worker-04');
    expect(drawer).toHaveTextContent('edge-gateway, dev-service, secrets-vault');
    expect(drawer).toHaveTextContent('14, 15, 16');
    expect(drawer).toHaveTextContent('GRAPH_MULTIHOP_TIER_ESCALATION');
    expect(drawer).toHaveTextContent('0.94');
    expect(drawer).toHaveTextContent('late_arrival: false');
    expect(screen.getByTestId('drawer-order-uncertain')).toHaveTextContent('order_uncertain: true');
    expect(screen.getByTestId('possible-orderings')).toHaveTextContent(
      'evt-15 (dev-service) -> evt-16 (secrets-vault)',
    );

    fireEvent.click(screen.getByTestId('alert-item-alrt-101'));
    expect(screen.getByTestId('alert-drawer')).toHaveTextContent('admin@urguard.local');
    expect(screen.getByTestId('alert-drawer')).toHaveTextContent('RULE_APPROVED_MAINT_ROTATION');
  });
});
