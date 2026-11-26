import type { ReactNode } from 'react';

interface CardProps {
  readonly title: string;
  readonly subtitle?: string;
  readonly actions?: ReactNode;
  readonly children: ReactNode;
}

/** Reusable panel card for operator console sections. */
export function Card({ title, subtitle, actions, children }: CardProps) {
  return (
    <section className="panel" aria-label={title}>
      <div className="panel-header">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p className="panel-summary">{subtitle}</p> : null}
        </div>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}
