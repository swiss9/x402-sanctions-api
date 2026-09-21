import { createHash, randomUUID } from "node:crypto";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import {
  AUDIT_RECEIPT_DOMAIN,
  AUDIT_RECEIPT_TYPES,
  type AuditReceiptPayload,
  type SignedAuditReceipt,
} from "./types.js";

// ─── SHA-256 Utilities ───────────────────────────────────────────────────────

export function sha256Hex(input: string): Hex {
  return `0x${createHash("sha256").update(input, "utf8").digest("hex")}` as Hex;
}

export function sha256HexFromBuffer(buf: Buffer): Hex {
  return `0x${createHash("sha256").update(buf).digest("hex")}` as Hex;
}

export function computeRequestHash(
  method: string,
  path: string,
  query: Record<string, string | string[] | undefined>
): Hex {
  const sortedParams = Object.entries(query)
    .filter(([, v]) => v !== undefined)
    .flatMap(([k, v]) =>
      Array.isArray(v)
        ? v.map((val) => [k, val] as [string, string])
        : [[k, v as string] as [string, string]]
    )
    .sort(([ka, va], [kb, vb]) => ka.localeCompare(kb) || va.localeCompare(vb))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");

  return sha256Hex(`${method.toUpperCase()}:${path}?${sortedParams}`);
}

// Recursive stable stringify: sorts object keys at every nesting level
// so the hash is deterministic regardless of key insertion order.
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const entries = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`
  );
  return `{${entries.join(",")}}`;
}

export function computeResponseHash(data: unknown): Hex {
  return sha256Hex(stableStringify(data));
}

export function computePaymentProofHash(paymentSignatureHeader: string): Hex {
  const decoded = Buffer.from(paymentSignatureHeader, "base64");
  return sha256HexFromBuffer(decoded);
}

// ─── EIP-712 Audit Receipt Signer ────────────────────────────────────────────

export class AuditReceiptSigner {
  private readonly account: PrivateKeyAccount;

  constructor(signingPrivateKey: Hex) {
    this.account = privateKeyToAccount(signingPrivateKey);
  }

  get signerAddress(): Address {
    return this.account.address;
  }

  async signReceipt(params: {
    requestHash: Hex;
    responseHash: Hex;
    paymentProofHash: Hex;
  }): Promise<SignedAuditReceipt> {
    const payload: AuditReceiptPayload = {
      receiptId: randomUUID(),
      timestamp: new Date().toISOString(),
      requestHash: params.requestHash,
      responseHash: params.responseHash,
      paymentProofHash: params.paymentProofHash,
      status: "DELIVERED",
    };

    const signature = await this.account.signTypedData({
      domain: AUDIT_RECEIPT_DOMAIN,
      types: AUDIT_RECEIPT_TYPES,
      primaryType: "Receipt",
      message: payload,
    });

    return {
      ...payload,
      signature,
      signerAddress: this.account.address,
    };
  }
}
