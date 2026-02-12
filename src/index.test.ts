import { describe, expect, it } from "bun:test";

import app, { type Env } from "./index";

const makeKVNamespace = (): KVNamespace => {
  // Per-test in-memory store so test runs are isolated and repeatable.
  const storage = new Map<string, string>();

  return {
    // The app under test reads user/movie records as plain text JSON.
    get: async (key: string) => storage.get(key) ?? null,
    getWithMetadata: async (key: string) => {
      const value = storage.get(key);
      if (value === undefined) {
        return { value: null, metadata: null };
      }
      return { value, metadata: null };
    },
    put: async (key: string, value: string | ArrayBuffer | ArrayBufferView) => {
      // Mirror KV behavior by accepting the value types allowed by Workers KV.
      if (typeof value === "string") {
        storage.set(key, value);
        return;
      }
      if (value instanceof ArrayBuffer) {
        storage.set(key, new TextDecoder().decode(value));
        return;
      }
      storage.set(
        key,
        new TextDecoder().decode(
          value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)
        )
      );
    },
    delete: async (key: string) => {
      storage.delete(key);
    },
    list: async () => ({
      // Minimal shape needed by the app's admin listing routes.
      keys: Array.from(storage.keys()).map((name) => ({
        name,
        expiration: undefined,
        metadata: undefined,
      })),
      list_complete: true,
      cursor: "",
    }),
    // Tests only use get/put/delete/list/getWithMetadata, so we provide that subset.
  } as unknown as KVNamespace;
};

const makeEnv = (): Env => ({
  JWT_SECRET_KEY: "test-secret",
  ADMIN_USERNAME: "admin",
  ADMIN_PASSWORD: "admin-password",
  SALT_ROUNDS: "4",
  USERS: makeKVNamespace(),
  MOVIES: makeKVNamespace(),
});

const signup = async (env: Env, username: string, password: string): Promise<Response> => {
  return await app.fetch(
    new Request("http://localhost/auth/signup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password }),
    }),
    env
  );
};

describe("signup password length guard", () => {
  it("accepts a password that is exactly 72 UTF-8 bytes", async () => {
    const env = makeEnv();
    const response = await signup(env, "exact72", "a".repeat(72));
    expect(response.status).toBe(201);
  });

  it("rejects a password that is longer than 72 UTF-8 bytes", async () => {
    const env = makeEnv();
    const response = await signup(env, "over72", "a".repeat(73));
    const body = (await response.json()) as { ok: boolean; message: string };

    expect(response.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.message).toBe(
      "Password is too long. Please choose a shorter password."
    );
  });

  it("uses byte length (not character count) for multibyte passwords", async () => {
    const env = makeEnv();

    const okResponse = await signup(env, "emoji72", "🙂".repeat(18));
    expect(okResponse.status).toBe(201);

    const tooLongResponse = await signup(env, "emoji76", "🙂".repeat(19));
    expect(tooLongResponse.status).toBe(400);
  });
});
