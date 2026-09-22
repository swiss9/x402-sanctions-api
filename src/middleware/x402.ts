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
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import type { SanctionsResult } from "../types.js";
import { NETWORK } from "../config.js";

// ─── AsyncLocalStorage for request-scoped context ────────────────────────────

export interface X402RequestContext {
  requestHash: string;
}

export const requestContext = new AsyncLocalStorage<X402RequestContext>();

// ─── Configuration ──────────────────────────────────────────────────────────

const MAX_TIMEOUT_SECONDS = 60;

// PayAI facilitator — permissionless, no API keys, no sign-up required.
// Supports Base Mainnet (eip155:8453) and other networks.
const PAYAI_FACILITATOR_URL = "https://facilitator.payai.network";

// ─── x402 Resource Server + Hook + Extension Registration ───────────────────

export function createX402Middleware(
  precomputeCache: LRUCache<string, SanctionsResult>
) {
  const paymentAddress = process.env.PAYMENT_ADDRESS;
  const signingPrivateKey = process.env.SIGNING_PRIVATE_KEY as Hex | undefined;

  if (!paymentAddress) throw new Error("PAYMENT_ADDRESS is required");
  if (!signingPrivateKey) throw new Error("SIGNING_PRIVATE_KEY is required");

  // PayAI facilitator client — standard HTTPFacilitatorClient interface.
  const facilitatorClient = new HTTPFacilitatorClient({
    url: PAYAI_FACILITATOR_URL,
  });

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
          price: "$$0.002",
          network: NETWORK,
          payTo: paymentAddress,
          maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
        },
      ],
      description:
        "OFAC SDN sanctions screening with fuzzy Jaro-Winkler matching. Returns screening results plus a signed audit-grade EIP-712 proof-of-execution receipt.",
      mimeType: "application/json",
      extensions: {
        // Receipt 1: proof of purchase (extension-signed)
        ...declareOfferReceiptExtension({ includeTxHash: false }),
        // Bazaar discovery metadata for agent discovery.
        // The HTTP method is inferred from the route key.
        ...declareDiscoveryExtension({
          input: { name: "John Doe", type: "individual" },
          inputSchema: {
            properties: {
              name: {
                type: "string",
                description: "The name to screen against the OFAC SDN list",
              },
              type: {
                type: "string",
                enum: ["individual", "entity", "vessel", "aircraft"],
                description: "The entity type to screen for",
              },
              threshold: {
                type: "number",
                description: "Jaro-Winkler threshold (0-1), default 0.85",
              },
            },
            required: ["name", "type"],
          },
          output: {
            example: {
              query: { name: "John Doe", type: "individual" },
              matched: true,
              matches: [
                {
                  sdnName: "John Doe",
                  sdnType: "individual",
                  programs: ["SDGT", "IRAN"],
                  score: 1.0,
                  matchType: "exact",
                  aliases: ["Johnny Doe", "J. Doe"],
                  remarks: "DOB 01 Jan 1970; POB Springfield",
                },
              ],
              screenedAt: "2026-09-21T15:00:00.000Z",
              sdnListVersion: "2026-09-20",
              processingTimeMs: 0.42,
            },
          },
        }),
      },
    },
  };

  return paymentMiddleware(routes, resourceServer);
}
