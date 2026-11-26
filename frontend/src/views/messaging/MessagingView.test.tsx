import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { createMockClient } from '../../mocks/mockClient.ts';
import { MessagingView } from './MessagingView.tsx';

describe('MessagingView', () => {
  it('supports E2E send, chunk reordering [2,0,3,1], and chunk drop [0,1,2]', async () => {
    const client = createMockClient();
    render(<MessagingView client={client} />);

    await waitFor(() => {
      expect(screen.getByTestId('chunk-visualiser')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Reorder chunks [2,0,3,1]' }));
    await waitFor(() => {
      expect(screen.getByTestId('messaging-result-code')).toHaveTextContent('DELIVERED');
      expect(screen.getByTestId('chunk-visualiser')).toHaveTextContent(
        'arrival order: [2, 0, 3, 1]',
      );
      expect(screen.getByTestId('matching-audit-event')).toHaveTextContent(
        'E2E_ENVELOPE_DELIVERED',
      );
    });

    fireEvent.click(screen.getByRole('button', { name: 'Drop chunk 1 of [0,1,2]' }));
    await waitFor(() => {
      expect(screen.getByTestId('messaging-result-code')).toHaveTextContent('DELIVERY_FAILED');
      expect(screen.getByTestId('chunk-tile-1')).toHaveTextContent('MISSING');
      expect(screen.getByTestId('chunk-visualiser')).toHaveTextContent('Plaintext Withheld');
    });
  });

  it('rejects envelope replay, recipient tampering, and mismatched session resumption', async () => {
    const client = createMockClient();
    render(<MessagingView client={client} />);

    await waitFor(() => {
      expect(screen.getByTestId('chunk-visualiser')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Replay captured envelope' }));
    await waitFor(() => {
      expect(screen.getByTestId('messaging-result-code')).toHaveTextContent('ERR_REPLAY_DETECTED');
      expect(screen.getByTestId('matching-audit-event')).toHaveTextContent('REPLAY_REJECTED');
    });

    fireEvent.click(screen.getByRole('button', { name: 'Tamper recipient_id' }));
    await waitFor(() => {
      expect(screen.getByTestId('messaging-result-code')).toHaveTextContent(
        'ERR_RECIPIENT_MISMATCH',
      );
      expect(screen.getByTestId('matching-audit-event')).toHaveTextContent(
        'RECIPIENT_BINDING_FAILED',
      );
    });

    fireEvent.click(screen.getByRole('button', { name: 'Resume session as different identity' }));
    await waitFor(() => {
      expect(screen.getByTestId('messaging-result-code')).toHaveTextContent(
        'ERR_SESSION_IDENTITY_MISMATCH',
      );
      expect(screen.getByTestId('matching-audit-event')).toHaveTextContent(
        'SESSION_HIJACK_ATTEMPT',
      );
      expect(screen.getByTestId('matching-alert-event')).toHaveTextContent(
        'SESSION_RESUMPTION_BINDING_MISMATCH',
      );
    });
  });
});
