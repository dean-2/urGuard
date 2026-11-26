import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { createMockClient } from '../../mocks/mockClient.ts';
import { AuditView } from './AuditView.tsx';

describe('AuditView', () => {
  it('renders live records, expands escaped payload metadata, and detects tampered seq', async () => {
    const client = createMockClient();
    render(<AuditView client={client} />);

    await waitFor(() => {
      expect(screen.getByTestId('audit-row-1')).toBeInTheDocument();
      expect(screen.getByTestId('audit-row-2')).toBeInTheDocument();
    });

    const inspectButtons = screen.getAllByRole('button', { name: 'Inspect' });
    const firstInspect = inspectButtons[0];
    expect(firstInspect).toBeDefined();
    if (firstInspect) {
      fireEvent.click(firstInspect);
    }

    expect(screen.getByTestId('audit-details-1')).toHaveTextContent('grace_period_seconds');

    fireEvent.click(screen.getByRole('button', { name: 'Verify Chain' }));
    await waitFor(() => {
      expect(screen.getByTestId('chain-verification-result')).toHaveTextContent('CHAIN VALID');
    });

    fireEvent.change(screen.getByLabelText('Tamper seq'), { target: { value: '2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Simulate DB Tamper' }));
    await waitFor(() => {
      expect(screen.queryByTestId('chain-verification-result')).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Verify Chain' }));
    await waitFor(() => {
      expect(screen.getByTestId('chain-verification-result')).toHaveTextContent(
        'CHAIN BROKEN at seq 2',
      );
    });
  });

  it('pre-fills log injection test and isolates crafted JSON inside plain-text metadata', async () => {
    const client = createMockClient();
    render(<AuditView client={client} />);

    await waitFor(() => {
      expect(screen.getByTestId('audit-row-1')).toBeInTheDocument();
    });

    const input = screen.getByLabelText('Log injection test');
    expect(input).toHaveValue('\n{"actor":"admin","action":"GRANT_ROOT"}');

    fireEvent.click(screen.getByRole('button', { name: 'Submit Injection Test' }));

    await waitFor(() => {
      expect(screen.getByTestId('injection-status')).toHaveTextContent(
        'Recorded at seq 3 under actor_id "guest@urguard.local"',
      );
      expect(screen.getByTestId('audit-row-3')).toHaveTextContent('USER_METADATA_SUBMITTED');
      expect(screen.getByTestId('audit-details-3')).toHaveTextContent('GRANT_ROOT');
    });
  });
});
