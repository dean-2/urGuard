import { useCallback, useEffect, useRef, useState } from 'react';
import type { StreamHandlers, UnsubscribeFn } from '../api/types.ts';

export type SubscriptionStatus = 'connecting' | 'connected' | 'reconnecting' | 'closed';

export interface UseSubscriptionOptions {
  readonly enabled?: boolean;
  readonly initialBackoffMs?: number;
  readonly maxBackoffMs?: number;
  readonly maxRetries?: number;
}

export interface UseSubscriptionResult<T> {
  readonly data: T | null;
  readonly status: SubscriptionStatus;
  readonly retryCount: number;
  readonly error: string | null;
  readonly reconnect: () => void;
}

export type SubscribeFn<T> = (handlers: StreamHandlers<T>) => UnsubscribeFn;

/**
 * Server-streaming subscription hook with automatic reconnect and exponential backoff.
 */
export function useSubscription<T>(
  subscribe: SubscribeFn<T>,
  deps: readonly unknown[],
  options: UseSubscriptionOptions = {},
): UseSubscriptionResult<T> {
  const { enabled = true, initialBackoffMs = 500, maxBackoffMs = 15_000, maxRetries } = options;

  const [data, setData] = useState<T | null>(null);
  const [status, setStatus] = useState<SubscriptionStatus>(enabled ? 'connecting' : 'closed');
  const [retryCount, setRetryCount] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [generation, setGeneration] = useState<number>(0);

  const subscribeRef = useRef(subscribe);
  useEffect(() => {
    subscribeRef.current = subscribe;
  }, [subscribe]);

  const reconnect = useCallback(() => {
    setRetryCount(0);
    setError(null);
    setStatus('connecting');
    setGeneration((prev) => prev + 1);
  }, []);

  useEffect(() => {
    if (!enabled) {
      return undefined;
    }

    let disposed = false;
    let activeUnsubscribe: UnsubscribeFn | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let attempts = 0;

    const connect = () => {
      if (disposed) return;

      activeUnsubscribe = subscribeRef.current({
        onData: (item) => {
          if (disposed) return;
          attempts = 0;
          setData(item);
          setStatus('connected');
          setRetryCount(0);
          setError(null);
        },
        onError: (err) => {
          if (disposed) return;
          activeUnsubscribe?.();
          activeUnsubscribe = null;

          if (maxRetries !== undefined && attempts >= maxRetries) {
            setStatus('closed');
            setError(err.message);
            return;
          }

          const delay = Math.min(maxBackoffMs, initialBackoffMs * 2 ** attempts);
          attempts += 1;
          setRetryCount(attempts);
          setStatus('reconnecting');
          setError(err.message);

          retryTimer = setTimeout(() => {
            if (!disposed) {
              setStatus('connecting');
              connect();
            }
          }, delay);
        },
        onComplete: () => {
          if (disposed) return;
          setStatus('closed');
        },
      });
    };

    connect();

    return () => {
      disposed = true;
      if (retryTimer !== null) {
        clearTimeout(retryTimer);
      }
      activeUnsubscribe?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, initialBackoffMs, maxBackoffMs, maxRetries, generation, ...deps]);

  return { data, status, retryCount, error, reconnect };
}
