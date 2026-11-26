import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMockClient } from '../../mocks/mockClient.ts';
import { GovernanceView } from './GovernanceView.tsx';

async function flushMicrotasks(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('GovernanceView', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('rotates key with live 30s grace countdown and transitions to CUTOFF_ENFORCED', async () => {
    vi.useFakeTimers();
    const client = createMockClient();
    render(<GovernanceView client={client} />);
    await flushMicrotasks();

    expect(screen.getByTestId('governance-current-epoch')).toHaveTextContent('Epoch 3');
    expect(screen.getByTestId('rotation-step-IDLE')).toHaveAttribute('aria-current', 'step');

    fireEvent.click(screen.getByRole('button', { name: 'Rotate key' }));
    await flushMicrotasks();

    expect(screen.getByTestId('governance-current-epoch')).toHaveTextContent('Epoch 4');
    expect(screen.getByTestId('rotation-step-COMMITTED')).toHaveAttribute('aria-current', 'step');
    expect(screen.getByTestId('grace-countdown')).toHaveTextContent('30s');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(screen.getByTestId('grace-countdown')).toHaveTextContent('25s');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(25_000);
      await Promise.resolve();
    });
    expect(screen.getByTestId('rotation-step-CUTOFF_ENFORCED')).toHaveAttribute(
      'aria-current',
      'step',
    );
  });

  it('streams staggered node acks on revocation and re-enrolls device excluding device_old', async () => {
    vi.useFakeTimers();
    const client = createMockClient();
    render(<GovernanceView client={client} />);
    await flushMicrotasks();

    fireEvent.click(screen.getByRole('button', { name: 'Revoke device' }));
    await flushMicrotasks();

    expect(screen.getByTestId('revocation-propagation-ms')).toHaveTextContent('114 ms');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(150);
    });

    expect(screen.getByText('node-a')).toBeInTheDocument();
    expect(screen.getByText('node-b')).toBeInTheDocument();
    expect(screen.getByText('node-c')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('New Device ID'), {
      target: { value: 'dev-alice-new-02' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Re-enroll device' }));
    await flushMicrotasks();

    const summary = screen.getByTestId('reenroll-summary');
    expect(summary).toHaveTextContent('dev-alice-new-02');
    expect(summary).toHaveTextContent('dev-alice-laptop is excluded');
    expect(summary).toHaveTextContent('EXCLUDED (REVOKED)');
  });

  it('detects 1-byte backup tamper with ERR_BACKUP_CORRUPTED and leaves live keys intact', async () => {
    const client = createMockClient();
    render(<GovernanceView client={client} />);
    await flushMicrotasks();

    fireEvent.click(screen.getByRole('button', { name: 'Export Backup' }));
    await flushMicrotasks();
    expect(screen.getByTestId('backup-tamper-state')).toHaveTextContent('INTACT');

    fireEvent.click(screen.getByRole('button', { name: 'Tamper 1 byte' }));
    expect(screen.getByTestId('backup-tamper-state')).toHaveTextContent('1-BYTE TAMPERED');

    fireEvent.click(screen.getByRole('button', { name: 'Restore Backup' }));
    await flushMicrotasks();

    const resultBanner = screen.getByTestId('backup-restore-result');
    expect(resultBanner).toHaveTextContent('ERR_BACKUP_CORRUPTED');
    expect(resultBanner).toHaveTextContent('live key material left untouched');
    expect(screen.getByTestId('governance-current-epoch')).toHaveTextContent('Epoch 3');
  });
});
