import { useCallback, useEffect, useRef, useState } from 'react';

export interface UseQueryOptions {
  readonly enabled?: boolean;
  readonly refetchIntervalMs?: number;
}

export interface UseQueryResult<T> {
  readonly data: T | null;
  readonly loading: boolean;
  readonly error: string | null;
  readonly refetch: () => Promise<void>;
}

/**
 * Generic async query hook with cancellation safety and optional polling interval.
 */
export function useQuery<T>(
  fetcher: () => Promise<T>,
  deps: readonly unknown[],
  options: UseQueryOptions = {},
): UseQueryResult<T> {
  const { enabled = true, refetchIntervalMs } = options;
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState<boolean>(enabled);
  const [error, setError] = useState<string | null>(null);

  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  }, [fetcher]);

  const execute = useCallback(async (isMounted?: () => boolean) => {
    try {
      const result = await fetcherRef.current();
      if (isMounted && !isMounted()) return;
      setData(result);
      setError(null);
    } catch (err) {
      if (isMounted && !isMounted()) return;
      setError(err instanceof Error ? err.message : 'Query failed');
    } finally {
      if (!isMounted || isMounted()) {
        setLoading(false);
      }
    }
  }, []);

  const refetch = useCallback(async () => {
    setLoading(true);
    await execute();
  }, [execute]);

  useEffect(() => {
    if (!enabled) {
      return undefined;
    }

    let active = true;
    const isMounted = () => active;

    void execute(isMounted);

    let intervalId: ReturnType<typeof setInterval> | undefined;
    if (refetchIntervalMs !== undefined && refetchIntervalMs > 0) {
      intervalId = setInterval(() => {
        void execute(isMounted);
      }, refetchIntervalMs);
    }

    return () => {
      active = false;
      if (intervalId !== undefined) {
        clearInterval(intervalId);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, refetchIntervalMs, execute, ...deps]);

  return { data, loading, error, refetch };
}
