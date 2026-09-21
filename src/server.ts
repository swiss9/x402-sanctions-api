import "dotenv/config";
import express, { type Request, type Response, type NextFunction } from "express";
import { LRUCache } from "lru-cache";
import { isAddress, type Hex } from "viem";
import {
  AuditReceiptSigner,
  computeResponseHash,
  computePaymentProofHash,
  computeRequestHash,
} from "./signer.js";
import { createX402Middleware, requestContext } from "./middleware/x402.js";
import { sanctionsService } from "./services/sanctions.js";
import { NETWORK, USDC_BASE, AMOUNT } from "./config.js";
import type {
  SanctionsQuery,
  EntityType,
  SanctionsResult,
  ApiResponseBody,
} from "./types.js";

// ─── Environment Validation ─────────────────────────────────────────────────

const PORT = Number(process.env.PORT || 3000);
const PAYMENT_ADDRESS = process.env.PAYMENT_ADDRESS;
const SIGNING_PRIVATE_KEY = process.env.SIGNING_PRIVATE_KEY as Hex | undefined;

if (!PAYMENT_ADDRESS || !isAddress(PAYMENT_ADDRESS)) {
  console.error("[FATAL] PAYMENT_ADDRESS is missing or not a valid EVM address.");
  process.exit(1);
}

if (!SIGNING_PRIVATE_KEY || !/^0x[0-9a-fA-F]{64}$/.test(SIGNING_PRIVATE_KEY)) {
  console.error("[FATAL] SIGNING_PRIVATE_KEY is missing or not a valid 32-byte hex key.");
  process.exit(1);
}

const signer = new AuditReceiptSigner(SIGNING_PRIVATE_KEY);

// ─── Pre-computation Cache ──────────────────────────────────────────────────

const precomputeCache = new LRUCache<string, SanctionsResult>({
  max: 500,
  ttl: 10 * 60 * 1000,
});

// ─── Rate Limiting ──────────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 30;
const RATE_LIMIT_RETRY_AFTER_S = 60;

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitStore.get(ip);

  if (!entry || now >= entry.resetAt) {
    rateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count += 1;
  return true;
}

// Lazy cleanup of expired entries to prevent unbounded memory growth.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitStore) {
    if (now >= entry.resetAt) rateLimitStore.delete(ip);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

// ─── Parameter Validation ───────────────────────────────────────────────────

const VALID_TYPES: ReadonlySet<string> = new Set<EntityType>([
  "individual",
  "entity",
  "vessel",
  "aircraft",
]);

interface ValidatedParams {
  name: string;
  type: EntityType;
  threshold?: number;
}

function validateQuery(
  req: Request
): { ok: true; params: ValidatedParams } | { ok: false; error: string } {
  const name = req.query.name;
  const type = req.query.type;

  if (!name || typeof name !== "string" || name.trim().length < 2) {
    return { ok: false, error: "Query parameter 'name' is required (min 2 characters)." };
  }
  if (name.trim().length > 200) {
    return { ok: false, error: "Query parameter 'name' must be 200 characters or fewer." };
  }
  if (!type || typeof type !== "string" || !VALID_TYPES.has(type)) {
    return {
      ok: false,
      error: `Query parameter 'type' is required and must be one of: ${[...VALID_TYPES].join(", ")}.`,
    };
  }

  let threshold: number | undefined;
  if (req.query.threshold !== undefined) {
    const raw = Number(req.query.threshold);
    if (Number.isNaN(raw) || raw < 0 || raw > 1) {
      return { ok: false, error: "Query parameter 'threshold' must be a number between 0 and 1." };
    }
    threshold = raw;
  }

  return {
    ok: true,
    params: { name: name.trim(), type: type as EntityType, threshold },
  };
}

// ─── Pre-computation Middleware ─────────────────────────────────────────────

function precomputeMiddleware(req: Request, res: Response, next: NextFunction): void {
  const ip = req.ip ?? "unknown";
  if (!checkRateLimit(ip)) {
    res.setHeader("Retry-After", String(RATE_LIMIT_RETRY_AFTER_S));
    res.status(429).json({ error: "Rate limit exceeded. Try again in 60 seconds." });
    return;
  }

  const validation = validateQuery(req);
  if (!validation.ok) {
    res.status(400).json({ error: validation.error });
    return;
  }

  // req.path is stripped of the mount prefix inside a mounted middleware,
  // so reconstruct the full path from baseUrl + path.
  const fullPath = req.baseUrl + req.path;
  const requestHash = computeRequestHash(
    req.method,
    fullPath,
    req.query as Record<string, string | string[] | undefined>
  );
  req.requestHash = requestHash;

  try {
    const query: SanctionsQuery = {
      name: validation.params.name,
      type: validation.params.type,
      threshold: validation.params.threshold,
    };
    const result = sanctionsService.screen(query);
    precomputeCache.set(requestHash, result);
    req.precomputedResult = result;
  } catch (err) {
    console.error("[precompute] Business logic failure:", err);
    res.status(502).json({ error: "Business logic failure. Please retry." });
    return;
  }

  requestContext.run({ requestHash }, () => next());
}

// ─── Express App ────────────────────────────────────────────────────────────

const app = express();

// Render terminates TLS at its edge proxy; trust the first hop so req.ip is
// the client's real IP rather than the proxy's.
app.set("trust proxy", 1);
app.use(express.json());

const x402Middleware = createX402Middleware(precomputeCache);

// Pre-computation is scoped to the paid endpoint only.
app.use("/v1/sanctions-check", precomputeMiddleware);
app.use(x402Middleware);

// ─── Route Handler ──────────────────────────────────────────────────────────

app.get("/v1/sanctions-check", async (req: Request, res: Response) => {
  const requestHash = req.requestHash;
  if (!requestHash) {
    res.status(500).json({ error: "Internal error: request hash not set." });
    return;
  }

  const result = precomputeCache.get(requestHash);
  if (!result) {
    res.status(500).json({ error: "Pre-computed result unavailable. This should never happen." });
    return;
  }

  const paymentSignature = req.headers["payment-signature"];
  if (!paymentSignature || typeof paymentSignature !== "string") {
    res.status(402).json({ error: "PAYMENT-SIGNATURE header is required." });
    return;
  }

  const responseHash = computeResponseHash(result);
  const paymentProofHash = computePaymentProofHash(paymentSignature);

  let signedReceipt;
  try {
    signedReceipt = await signer.signReceipt({
      requestHash: requestHash as Hex,
      responseHash,
      paymentProofHash,
    });
  } catch (err) {
    console.error("[handler] Failed to sign audit receipt:", err);
    res.status(500).json({ error: "Failed to sign audit receipt." });
    return;
  }

  const body: ApiResponseBody = { data: result, _audit: signedReceipt };
  res.status(200).json(body);
});

// ─── Health Check ───────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    signerAddress: signer.signerAddress,
    payTo: PAYMENT_ADDRESS,
    network: NETWORK,
    asset: USDC_BASE,
    amount: AMOUNT,
    facilitator: process.env.FACILITATOR_URL || "https://v2.facilitator.mogami.tech",
  });
});

// ─── Global Error Handler ───────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[global] Unhandled error:", err);
  res.status(500).json({ error: "Internal server error." });
});

// ─── Start ──────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║  x402 OFAC Sanctions Screening API — Audit-Grade               ║
╠══════════════════════════════════════════════════════════════════╣
║  Network:        ${NETWORK} (Base Mainnet)
║  Asset:          USDC (${USDC_BASE.slice(0, 6)}...${USDC_BASE.slice(-4)})
║  Price:          0.01 USDC per call
║  Pay To:         ${PAYMENT_ADDRESS}
║  Signer:         ${signer.signerAddress}
║  Facilitator:    ${process.env.FACILITATOR_URL || "https://v2.facilitator.mogami.tech"}
║  Endpoint:       GET /v1/sanctions-check
╚══════════════════════════════════════════════════════════════════╝
  `);
});
