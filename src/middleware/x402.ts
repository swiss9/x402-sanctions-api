import { AsyncLocalStorage } from "node:async_hooks";
import type { Request, Response, NextFunction } from "express";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import { LRUCache } from "lru-cache";
import { x402ResourceServer } from "@x402/express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { paymentMiddleware } from "@x402/express";
import {
  createOfferReceiptExtension,
  createEIP712OfferReceiptIssuer,
  declareOfferReceiptExtension,
} from "@x402/extensions/offer-receipt";
import type { SanctionsResult } from "../types.js";
import { NETWORK } from "../config.js";

// ─── AsyncLocalStorage for request-scoped context ────────────────────────────

export interface X402RequestContext {
  requestHash: string;
}

export const requestContext = new AsyncLocalStorage<X402RequestContext>();

// ─── Configuration ──────────────────────────────────────────────────────────

const MAX_TIMEOUT_SECONDS = 60;

// ─── x402 Resource Server + Hook + Extension Registration ───────────────────

export function createX402Middleware(
  precomputeCache: LRUCache<string, SanctionsResult>
) {
  const paymentAddress = process.env.PAYMENT_ADDRESS;
  const signingPrivateKey = process.env.SIGNING_PRIVATE_KEY as Hex | undefined;
  const facilitatorUrl =
    process.env.FACILITATOR_URL || "https://v2.facilitator.mogami.tech";

  if (!paymentAddress) throw new Error("PAYMENT_ADDRESS is required");
  if (!signingPrivateKey) throw new Error("SIGNING_PRIVATE_KEY is required");

  const facilitatorClient = new HTTPFacilitatorClient({ url: facilitatorUrl });

  // Receipt 1 (proof of purchase) — extension-signed EIP-712 receipt.
  const signingAccount = privateKeyToAccount(signingPrivateKey);
  const kid = `did:pkh:eip155:1:${signingAccount.address}#key-1`;
  const issuer = createEIP712OfferReceiptIssuer(
    kid,
    signingAccount.signTypedData.bind(signingAccount),
  );

  const resourceServer = new x402ResourceServer(facilitatorClient)
    .register(NETWORK, new ExactEvmScheme())
    .registerExtension(createOfferReceiptExtension(issuer))
    .onBeforeSettle(async (context) => {
      if (context.phase !== "after-handler") return;
      const store = requestContext.getStore();
      if (!store || !precomputeCache.has(store.requestHash)) {
        return { abort: true, reason: "precomputed result unavailable" };
      }
    });

  const routes = {
    "GET /v1/sanctions-check": {
      accepts: [
        {
          scheme: "exact" as const,
          price: "$0.01",
          network: NETWORK,
          payTo: paymentAddress,
          maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
        },
      ],
      description:
        "OFAC SDN sanctions screening with fuzzy Jaro-Winkler matching. Returns screening results plus a signed audit-grade EIP-712 proof-of-execution receipt.",
      mimeType: "application/json",
      extensions: {
        ...declareOfferReceiptExtension({ includeTxHash: false }),
      },
    },
  };

  return paymentMiddleware(routes, resourceServer);
}
