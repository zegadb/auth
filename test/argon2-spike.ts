import { argon2id, setWASMModules } from 'argon2-wasm-edge';
// @ts-expect-error Wrangler compiles these into WebAssembly.Module imports.
import argon2WASM from 'argon2-wasm-edge/wasm/argon2.wasm';
// @ts-expect-error Wrangler compiles these into WebAssembly.Module imports.
import blake2bWASM from 'argon2-wasm-edge/wasm/blake2b.wasm';

export default {
  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') return new Response('POST JSON {password}', { status: 405 });
    const { password } = await request.json() as { password?: unknown };
    if (typeof password !== 'string' || password.length < 1) return Response.json({ error: 'password_required' }, { status: 400 });
    await setWASMModules({ argon2WASM, blake2bWASM });
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const started = performance.now();
    await argon2id({ password, salt, iterations: 2, memorySize: 19_456, parallelism: 1, hashLength: 32, outputType: 'encoded' });
    const cpuMs = Math.round((performance.now() - started) * 100) / 100;
    return Response.json({ cpuMs, memoryKiB: 19_456, iterations: 2, parallelism: 1 });
  },
};
