#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';

function parseArgs(argv) {
  const out = {
    wasmPath: '',
    profile: 'base',
    iterations: 50000,
    warmup: 5000,
    headless: true,
  };

  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    switch (key) {
      case '--wasm-path':
        out.wasmPath = argv[++i] ?? '';
        break;
      case '--profile':
        out.profile = argv[++i] ?? 'base';
        break;
      case '--iterations':
        out.iterations = Number.parseInt(argv[++i] ?? '', 10);
        break;
      case '--warmup':
        out.warmup = Number.parseInt(argv[++i] ?? '', 10);
        break;
      case '--headed':
        out.headless = false;
        break;
      case '--help':
      case '-h':
        console.log('usage: run_browser_wasm_bench.mjs --wasm-path <path> --profile <base|stress> --iterations <n> --warmup <n> [--headed]');
        process.exit(0);
      default:
        throw new Error(`unknown argument: ${key}`);
    }
  }

  if (!out.wasmPath) {
    throw new Error('--wasm-path is required');
  }
  if (!Number.isFinite(out.iterations) || out.iterations <= 0) {
    throw new Error(`invalid --iterations value: ${out.iterations}`);
  }
  if (!Number.isFinite(out.warmup) || out.warmup < 0) {
    throw new Error(`invalid --warmup value: ${out.warmup}`);
  }
  if (!['base', 'stress'].includes(out.profile)) {
    throw new Error(`unsupported --profile value: ${out.profile} (expected base|stress)`);
  }

  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const requireFromCwd = createRequire(path.join(process.cwd(), 'package.json'));
  let chromium;
  try {
    ({ chromium } = requireFromCwd('playwright'));
  } catch (error) {
    throw new Error(
      'playwright package not available from current directory. Run npm ci in examples/tests/playwright and re-run this command from that directory.'
    );
  }

  const wasmBytes = await readFile(args.wasmPath);
  const wasmBase64 = wasmBytes.toString('base64');

  const profileId = args.profile === 'stress' ? 1 : 0;

  const browser = await chromium.launch({ headless: args.headless });
  try {
    const page = await browser.newPage();
    await page.goto('about:blank');

    const payload = {
      wasmBase64,
      profileId,
      iterations: args.iterations,
      warmup: args.warmup,
    };

    const result = await page.evaluate(async ({ wasmBase64, profileId, iterations, warmup }) => {
      const binary = Uint8Array.from(atob(wasmBase64), (char) => char.charCodeAt(0));
      const { instance } = await WebAssembly.instantiate(binary.buffer, {});
      const { exports } = instance;

      if (typeof exports.bench_vectors !== 'function' || typeof exports.bench_run !== 'function') {
        throw new Error('missing expected wasm exports: bench_vectors/bench_run');
      }

      const vectors = Number(exports.bench_vectors(profileId));
      if (!Number.isFinite(vectors) || vectors <= 0) {
        throw new Error(`invalid vector count returned from wasm module: ${vectors}`);
      }

      const started = performance.now();
      const rawChecksum = exports.bench_run(profileId, iterations, warmup);
      const elapsedMs = performance.now() - started;

      const checksumBigInt = typeof rawChecksum === 'bigint'
        ? rawChecksum
        : BigInt(rawChecksum >>> 0);
      const checksumU64 = checksumBigInt & ((1n << 64n) - 1n);

      return {
        vectors,
        elapsed_ns: Math.round(elapsedMs * 1_000_000),
        checksum: checksumU64.toString(16).padStart(16, '0').slice(-16),
      };
    }, payload);

    const ops = args.iterations * result.vectors;
    const opsPerSec = result.elapsed_ns === 0
      ? 0
      : (ops * 1_000_000_000) / result.elapsed_ns;

    const output = {
      language: 'wasm-browser',
      engine: 'chromium',
      profile: args.profile,
      vectors: result.vectors,
      iterations: args.iterations,
      ops,
      elapsed_ns: result.elapsed_ns,
      ops_per_sec: Number(opsPerSec.toFixed(3)),
      checksum: result.checksum,
    };

    console.log(JSON.stringify(output));
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error.message || String(error));
  process.exit(1);
});
