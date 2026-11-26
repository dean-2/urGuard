import { useCallback, useMemo, useState } from 'react';
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react';
import '@xyflow/react/style.css';
import type { UrGuardClient } from '../../api/client.ts';
import type {
  AccessGraph,
  AccessGraphNode,
  DetectionMetrics,
  SecurityAlert,
} from '../../api/types.ts';
import { Badge, Card, StatusBanner } from '../../components/index.ts';
import { useQuery, useSubscription } from '../../hooks/index.ts';

interface DetectionViewProps {
  readonly client: UrGuardClient;
}

function severityTone(severity: SecurityAlert['severity']): 'danger' | 'warning' | 'info' {
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'danger';
  if (severity === 'MEDIUM') return 'warning';
  return 'info';
}

function layoutGraphNodes(graphNodes: readonly AccessGraphNode[]): Node[] {
  const byColumn: Record<AccessGraphNode['kind'], AccessGraphNode[]> = {
    IDENTITY: [],
    SERVICE: [],
    ENCLAVE: [],
  };

  graphNodes.forEach((node) => {
    byColumn[node.kind].push(node);
  });

  const xByKind: Record<AccessGraphNode['kind'], number> = {
    IDENTITY: 40,
    SERVICE: 320,
    ENCLAVE: 600,
  };

  const laidOut: Node[] = [];
  (['IDENTITY', 'SERVICE', 'ENCLAVE'] as const).forEach((kind) => {
    byColumn[kind].forEach((node, index) => {
      laidOut.push({
        id: node.id,
        position: { x: xByKind[kind], y: 30 + index * 110 },
        data: {
          label: `${node.label} (T${String(node.trustTier)})`,
        },
        style: {
          background: node.kind === 'ENCLAVE' ? '#251722' : '#161b22',
          color: '#e6edf3',
          border: node.kind === 'ENCLAVE' ? '1px solid #f85149' : '1px solid #388bfd',
          borderRadius: 8,
          padding: '8px 12px',
          fontSize: 12,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        },
      });
    });
  });

  return laidOut;
}

/** Deterministic rule + graph lateral movement detector and evaluation metrics view. */
export function DetectionView({ client }: DetectionViewProps) {
  const fetchGraph = useCallback(() => client.getAccessGraph(), [client]);
  const fetchMetrics = useCallback(() => client.getMetrics(), [client]);
  const subscribeAlerts = useCallback(
    (handlers: Parameters<UrGuardClient['subscribeAlerts']>[0]) => client.subscribeAlerts(handlers),
    [client],
  );

  const { data: graphData, error: graphError } = useQuery<AccessGraph>(fetchGraph, [client]);
  const { data: metrics, error: metricsError } = useQuery<DetectionMetrics>(fetchMetrics, [client]);
  const {
    data: alertsData,
    status: streamStatus,
    error: alertStreamError,
  } = useSubscription<readonly SecurityAlert[]>(subscribeAlerts, [client]);

  const alerts = useMemo(() => alertsData ?? [], [alertsData]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedNodeLabel, setSelectedNodeLabel] = useState<string | null>(null);

  const selectedAlert = useMemo(() => {
    if (selectedAlertId) {
      const exact = alerts.find((a) => a.alertId === selectedAlertId);
      if (exact) return exact;
    }
    if (selectedNodeLabel) {
      const byNode = alerts.find(
        (a) => a.identity === selectedNodeLabel || a.services.includes(selectedNodeLabel),
      );
      if (byNode) return byNode;
    }
    return alerts.find((a) => a.orderUncertain) ?? alerts[0] ?? null;
  }, [alerts, selectedAlertId, selectedNodeLabel]);

  const flowNodes = useMemo(() => layoutGraphNodes(graphData?.nodes ?? []), [graphData]);

  const flowEdges = useMemo<Edge[]>(
    () =>
      (graphData?.edges ?? []).map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: edge.flagged,
        label: edge.flagged
          ? `${edge.identity} · FLAGGED`
          : `${edge.identity} (${String(edge.baselineCount)})`,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: edge.flagged ? '#f85149' : '#8b949e',
        },
        style: {
          stroke: edge.flagged ? '#f85149' : '#58a6ff',
          strokeWidth: edge.flagged ? 2.5 : 1.5,
        },
        labelStyle: {
          fill: edge.flagged ? '#ffa198' : '#8b949e',
          fontSize: 11,
        },
      })),
    [graphData],
  );

  return (
    <div className="view-stack">
      {graphError || metricsError || alertStreamError ? (
        <StatusBanner tone="danger" title="Detection telemetry error">
          {graphError ?? metricsError ?? alertStreamError}
        </StatusBanner>
      ) : null}

      <Card
        title="Explainable Detection Metrics (Zero AI/ML)"
        subtitle="Deterministic rule + graph traversal evaluation metrics on labeled synthetic & live event streams."
        actions={
          <Badge tone={streamStatus === 'connected' ? 'success' : 'warning'}>
            feed: {streamStatus}
          </Badge>
        }
      >
        <div className="kpi-grid">
          <div className="kpi-card">
            <span className="kpi-label">Precision</span>
            <strong className="kpi-value" data-testid="kpi-precision">
              {metrics ? metrics.precision.toFixed(2) : '--'}
            </strong>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">Recall</span>
            <strong className="kpi-value" data-testid="kpi-recall">
              {metrics ? metrics.recall.toFixed(2) : '--'}
            </strong>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">F1 Score</span>
            <strong className="kpi-value" data-testid="kpi-f1">
              {metrics ? metrics.f1Score.toFixed(2) : '--'}
            </strong>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">Median Time to Alert</span>
            <strong className="kpi-value" data-testid="kpi-alert-latency">
              {metrics ? `${String(metrics.medianTimeToAlertMs)} ms` : '--'}
            </strong>
          </div>
          <div className="kpi-card">
            <span className="kpi-label">False Alerts / 1k Benign</span>
            <strong className="kpi-value" data-testid="kpi-false-alerts">
              {metrics ? String(metrics.falseAlertsPer1kBenign) : '--'}
            </strong>
          </div>
        </div>
      </Card>

      <Card
        title="Identity → Service Lateral Movement Graph"
        subtitle="Directed multigraph highlighting unseen cross-service pivots and multi-hop trust-tier escalations."
      >
        <div className="graph-canvas" data-testid="access-graph-canvas">
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            fitView
            onNodeClick={(_event, node) => {
              const matched = graphData?.nodes.find((n) => n.id === node.id);
              if (matched) {
                setSelectedAlertId(null);
                setSelectedNodeLabel(matched.label);
              }
            }}
          >
            <Controls />
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
          </ReactFlow>
        </div>
        <div className="meta-row subsection">
          {(graphData?.edges ?? []).map((edge) => (
            <Badge key={edge.id} tone={edge.flagged ? 'danger' : 'neutral'}>
              {edge.source} → {edge.target} ({edge.flagged ? 'FLAGGED' : 'BASELINE'})
            </Badge>
          ))}
        </div>
      </Card>

      <div className="detection-split">
        <Card
          title="Live Alert Feed"
          subtitle="Click any alert to inspect causal path, evidence events, and clock-skew uncertainty."
        >
          <div className="alert-feed" data-testid="live-alert-feed">
            {alerts.map((alert) => {
              const isSelected = selectedAlert?.alertId === alert.alertId;
              return (
                <button
                  key={alert.alertId}
                  type="button"
                  className={`alert-item ${isSelected ? 'selected' : ''}`}
                  data-testid={`alert-item-${alert.alertId}`}
                  onClick={() => {
                    setSelectedAlertId(alert.alertId);
                  }}
                >
                  <div className="meta-row">
                    <Badge tone={severityTone(alert.severity)}>{alert.severity}</Badge>
                    <Badge tone="neutral">{alert.classification}</Badge>
                    {alert.orderUncertain ? <Badge tone="warning">order_uncertain</Badge> : null}
                    {alert.lateArrival ? <Badge tone="info">late_arrival</Badge> : null}
                  </div>
                  <div className="alert-item-title">
                    {alert.identity} — {alert.pathOrRule}
                  </div>
                </button>
              );
            })}
          </div>
        </Card>

        <Card title="Alert Explanation Drawer" subtitle="Auditable rule & graph evidence">
          {selectedAlert ? (
            <div className="alert-drawer" data-testid="alert-drawer">
              <div className="meta-row">
                <Badge tone={severityTone(selectedAlert.severity)}>{selectedAlert.severity}</Badge>
                <Badge tone="info">{selectedAlert.alertId}</Badge>
                {selectedAlert.orderUncertain ? (
                  <Badge tone="warning" testId="drawer-order-uncertain">
                    order_uncertain: true
                  </Badge>
                ) : (
                  <Badge tone="success">order_uncertain: false</Badge>
                )}
                <Badge tone={selectedAlert.lateArrival ? 'warning' : 'neutral'}>
                  late_arrival: {String(selectedAlert.lateArrival)}
                </Badge>
              </div>

              <dl className="detail-list">
                <dt>identity</dt>
                <dd className="mono">{selectedAlert.identity}</dd>

                <dt>services[]</dt>
                <dd className="mono">{selectedAlert.services.join(', ')}</dd>

                <dt>event_ids[]</dt>
                <dd className="mono">{selectedAlert.eventIds.map(String).join(', ')}</dd>

                <dt>path_or_rule</dt>
                <dd className="mono">{selectedAlert.pathOrRule}</dd>

                <dt>confidence_score</dt>
                <dd className="mono">{selectedAlert.confidenceScore.toFixed(2)}</dd>

                <dt>explanation</dt>
                <dd>{selectedAlert.explanation}</dd>
              </dl>

              {selectedAlert.orderUncertain && selectedAlert.possibleOrderings ? (
                <div className="subsection" data-testid="possible-orderings">
                  <strong>Possible causal orderings (within 2 × skew bound):</strong>
                  <ul className="panel-list">
                    {selectedAlert.possibleOrderings.map((ordering) => (
                      <li key={ordering} className="mono">
                        {ordering}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : (
            <p className="muted">Select an alert from the feed to inspect details.</p>
          )}
        </Card>
      </div>
    </div>
  );
}
