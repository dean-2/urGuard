import type { ReactNode } from 'react';

export type BadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'info';

interface BadgeProps {
  readonly tone?: BadgeTone;
  readonly children: ReactNode;
  readonly testId?: string;
}

/** Compact pill badge for node health, protocol codes, and verification results. */
export function Badge({ tone = 'neutral', children, testId }: BadgeProps) {
  return (
    <span className={`badge badge-${tone}`} data-testid={testId}>
      {children}
    </span>
  );
}
