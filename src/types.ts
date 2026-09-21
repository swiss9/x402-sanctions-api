// ─── OFAC Query Types ────────────────────────────────────────────────────────

export type EntityType = "individual" | "entity" | "vessel" | "aircraft";

export interface SanctionsQuery {
  name: string;
  type: EntityType;
  threshold?: number;
}

export interface SanctionsMatch {
  sdnName: string;
  sdnType: string;
  programs: string[];
  score: number;
  matchType: "exact" | "fuzzy" | "alias";
  aliases: string[];
  remarks: string;
}

export interface SanctionsResult {
  query: SanctionsQuery;
  matched: boolean;
  matches: SanctionsMatch[];
  screenedAt: string;
  sdnListVersion: string;
  processingTimeMs: number;
}

// ─── x402 v2 Header Types ────────────────────────────────────────────────────

export interface PaymentRequiredObject {
  x402Version: 2;
  accepts: PaymentRequirements[];
  error?: string;
  resource?: string;
}

export interface PaymentRequirements {
  scheme: "exact";
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
}

export interface SettlementResponseObject {
  success: boolean;
  transaction?: string;
  network: string;
  payer?: string;
  errorReason?: string;
}

// ─── Custom EIP-712 Audit Receipt ────────────────────────────────────────────

export interface AuditReceiptPayload {
  receiptId: string;
  timestamp: string;
  requestHash: string;
  responseHash: string;
  paymentProofHash: string;
  status: "DELIVERED";
}

export interface SignedAuditReceipt extends AuditReceiptPayload {
  signature: string;
  signerAddress: string;
}

export const AUDIT_RECEIPT_DOMAIN = {
  name: "AuditGradeExecutionReceipt",
  version: "1.0.0",
  chainId: 8453,
} as const;

export const AUDIT_RECEIPT_TYPES = {
  Receipt: [
    { name: "receiptId", type: "string" },
    { name: "timestamp", type: "string" },
    { name: "requestHash", type: "string" },
    { name: "responseHash", type: "string" },
    { name: "paymentProofHash", type: "string" },
    { name: "status", type: "string" },
  ],
} as const;

// ─── API Response Envelope ───────────────────────────────────────────────────

export interface ApiResponseBody {
  data: SanctionsResult;
  _audit: SignedAuditReceipt;
}

// ─── Express Request Augmentation ────────────────────────────────────────────

declare global {
  namespace Express {
    interface Request {
      requestHash?: string;
      precomputedResult?: SanctionsResult;
    }
  }
}
