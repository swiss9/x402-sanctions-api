export const X402_DISCOVERY_MANIFEST = {
  x402Version: 2,
  name: "OFAC Sanctions Screening API",
  description: "OFAC SDN sanctions screening with fuzzy Jaro-Winkler matching. Returns results plus a signed EIP-712 proof-of-execution receipt.",
  endpoints: [
    {
      path: "/v1/sanctions-check",
      method: "GET",
      description: "Screen an individual, entity, vessel, or aircraft name against the OFAC SDN sanctions list.",
      input: {
        query: {
          name: { type: "string", required: true, description: "The name to screen" },
          type: { type: "string", required: true, enum: ["individual", "entity", "vessel", "aircraft"] },
          threshold: { type: "number", required: false, description: "Jaro-Winkler threshold (0-1), default 0.85" },
        },
      },
      output: {
        example: {
          query: { name: "John Doe", type: "individual" },
          matched: true,
          matches: [{ sdnName: "John Doe", score: 1.0, matchType: "exact" }],
          screenedAt: "2026-09-21T15:00:00.000Z",
        },
      },
      payment: {
        scheme: "exact",
        network: "eip155:8453",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        amount: "10000",
        payTo: process.env.PAYMENT_ADDRESS,
      },
    },
  ],
};
