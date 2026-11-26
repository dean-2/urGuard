import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { StreamHandlers } from '../api/types.ts';
import { useQuery } from './useQuery.ts';
import { useSubscription } from './useSubscription.ts';

describe('useQuery', () => {
  it('fetches data, handles errors, and supports manual refetch', async () => {
    let count = 0;
    const fetcher = vi.fn(() => {
      count += 1;
      if (count === 2) {
        return Promise.reject(new Error('temporary error'));
      }
      return Promise.resolve(`value-${String(count)}`);
    });

    const { result } = renderHook(() => useQuery(fetcher, []));
    expect(result.current.loading).toBe(true);

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
      expect(result.current.data).toBe('value-1');
    });

    await act(async () => {
      await result.current.refetch();
    });
    expect(result.current.error).toBe('temporary error');

    await act(async () => {
      await result.current.refetch();
    });
    expect(result.current.error).toBeNull();
    expect(result.current.data).toBe('value-3');
  });
});

describe('useSubscription', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('reconnects with exponential backoff and recovers on stream data', async () => {
    vi.useFakeTimers();
    let attempt = 0;

    const subscribe = vi.fn((handlers: StreamHandlers<string>) => {
      attempt += 1;
      if (attempt <= 2) {
        queueMicrotask(() => {
          handlers.onError?.(new Error(`stream dropped #${String(attempt)}`));
        });
      } else {
        queueMicrotask(() => {
          handlers.onData('stream-recovered');
        });
      }
      return () => undefined;
    });

    const { result } = renderHook(() =>
      useSubscription(subscribe, [], { initialBackoffMs: 100, maxBackoffMs: 1000 }),
    );

    expect(result.current.status).toBe('connecting');

    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.status).toBe('reconnecting');
    expect(result.current.retryCount).toBe(1);
    expect(result.current.error).toBe('stream dropped #1');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(100);
      await Promise.resolve();
    });
    expect(result.current.status).toBe('reconnecting');
    expect(result.current.retryCount).toBe(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(199);
    });
    expect(result.current.status).toBe('reconnecting');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
      await Promise.resolve();
    });
    expect(result.current.status).toBe('connected');
    expect(result.current.retryCount).toBe(0);
    expect(result.current.data).toBe('stream-recovered');
    expect(result.current.error).toBeNull();
  });

  it('transitions to closed once maxRetries is exceeded', async () => {
    vi.useFakeTimers();

    const subscribe = vi.fn((handlers: StreamHandlers<string>) => {
      queueMicrotask(() => {
        handlers.onError?.(new Error('fatal stream failure'));
      });
      return () => undefined;
    });

    const { result } = renderHook(() =>
      useSubscription(subscribe, [], {
        initialBackoffMs: 50,
        maxBackoffMs: 500,
        maxRetries: 1,
      }),
    );

    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.status).toBe('reconnecting');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(50);
      await Promise.resolve();
    });
    expect(result.current.status).toBe('closed');
    expect(result.current.error).toBe('fatal stream failure');
  });
});
