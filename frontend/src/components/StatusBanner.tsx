import type { ReactNode } from 'react';

interface StatusBannerProps {
  readonly tone: 'info' | 'success' | 'warning' | 'danger';
  readonly title?: string;
  readonly children: ReactNode;
  readonly testId?: string;
}

/** Accessible alert/status banner rendered strictly with React text/children. */
export function StatusBanner({ tone, title, children, testId }: StatusBannerProps) {
  return (
    <div className={`status-banner status-banner-${tone}`} role="status" data-testid={testId}>
      {title ? <strong className="status-banner-title">{title}: </strong> : null}
      <span>{children}</span>
    </div>
  );
}
