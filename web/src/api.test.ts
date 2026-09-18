import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("API request deadline", () => {
  it("aborts a hung bootstrap read and reports a retryable timeout", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn((_path: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = expect(api.bootstrapState()).rejects.toMatchObject({
      code: "hub_timeout",
      recoveryAction: "retry_later",
    });
    await vi.advanceTimersByTimeAsync(15_000);
    await result;
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).signal?.aborted).toBe(true);
  });
});
