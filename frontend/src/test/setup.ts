import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

class ResizeObserverShim {
  private readonly callback: ResizeObserverCallback;

  constructor(callback: ResizeObserverCallback) {
    this.callback = callback;
  }

  observe(target: Element): void {
    setTimeout(() => {
      this.callback([{ target } as ResizeObserverEntry], this);
    }, 0);
  }

  unobserve(): void {
    // No-op in jsdom
  }

  disconnect(): void {
    // No-op in jsdom
  }
}

class DOMMatrixReadOnlyShim {
  readonly m22: number;

  constructor(transform = '') {
    const match = /scale\(([0-9.]+)\)/.exec(transform);
    this.m22 = match?.[1] ? Number(match[1]) : 1;
  }
}

if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = ResizeObserverShim;
}

if (typeof globalThis.DOMMatrixReadOnly === 'undefined') {
  globalThis.DOMMatrixReadOnly = DOMMatrixReadOnlyShim as unknown as typeof DOMMatrixReadOnly;
}

Object.defineProperties(HTMLElement.prototype, {
  offsetHeight: {
    configurable: true,
    get(this: HTMLElement) {
      return Number.parseFloat(this.style.height) || 120;
    },
  },
  offsetWidth: {
    configurable: true,
    get(this: HTMLElement) {
      return Number.parseFloat(this.style.width) || 200;
    },
  },
});

if (typeof SVGElement !== 'undefined') {
  Object.defineProperty(SVGElement.prototype, 'getBBox', {
    configurable: true,
    value: () => ({ x: 0, y: 0, width: 120, height: 40 }),
  });
}

afterEach(() => {
  cleanup();
});
