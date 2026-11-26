import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it } from 'vitest';
import { createMockClient } from '../mocks/mockClient.ts';
import { App } from './App.tsx';

describe('App shell & routing', () => {
  it('renders sidebar routes, cluster health header, and MessagingView on root', async () => {
    const client = createMockClient();
    render(
      <MemoryRouter initialEntries={['/']}>
        <App client={client} />
      </MemoryRouter>,
    );

    expect(screen.getByText('urGuard')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Messaging' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Key Governance' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Audit Log' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Detection' })).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId('health-controlplane')).toHaveTextContent('controlplane: READY');
      expect(screen.getByTestId('health-node-a')).toHaveTextContent('node-a: HEALTHY');
      expect(screen.getByTestId('health-node-b')).toHaveTextContent('node-b: HEALTHY');
      expect(screen.getByTestId('health-node-c')).toHaveTextContent('node-c: HEALTHY');
      expect(screen.getByTestId('active-epoch')).toHaveTextContent('epoch: 3');
      expect(screen.getByTestId('chunk-visualiser')).toBeInTheDocument();
    });
  });

  it('renders Key Governance, Audit Log, and Detection views on their routes', async () => {
    const client = createMockClient();

    const gov = render(
      <MemoryRouter initialEntries={['/governance']}>
        <App client={client} />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('governance-current-epoch')).toHaveTextContent('Epoch 3');
    });
    gov.unmount();

    const audit = render(
      <MemoryRouter initialEntries={['/audit']}>
        <App client={client} />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('audit-row-1')).toBeInTheDocument();
    });
    audit.unmount();

    render(
      <MemoryRouter initialEntries={['/detection']}>
        <App client={client} />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('kpi-f1')).toHaveTextContent('0.96');
      expect(screen.getByTestId('alert-drawer')).toBeInTheDocument();
    });
  });
});
