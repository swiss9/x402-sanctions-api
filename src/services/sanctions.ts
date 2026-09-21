import natural from "natural";
import type {
  SanctionsQuery,
  SanctionsResult,
  SanctionsMatch,
  EntityType,
} from "../types.js";

// ─── Static SDN Dataset (subset for demonstration) ──────────────────────────
// In production, load from the OFAC SDN XML/CSV published by the U.S. Treasury.

interface SdnRecord {
  name: string;
  type: EntityType;
  programs: string[];
  aliases: string[];
  remarks: string;
}

const SDN_LIST_VERSION = "2026-09-20";

const SDN_RECORDS: SdnRecord[] = [
  {
    name: "John Doe",
    type: "individual",
    programs: ["SDGT", "IRAN"],
    aliases: ["Johnny Doe", "J. Doe"],
    remarks: "DOB 01 Jan 1970; POB Springfield",
  },
  {
    name: "Acme Trading Corp",
    type: "entity",
    programs: ["NPWMD"],
    aliases: ["Acme Trading Corporation", "ATC"],
    remarks: "Registration #12345",
  },
  {
    name: "Ivan Petrov",
    type: "individual",
    programs: ["UKRAINE-EO13662"],
    aliases: ["I. Petrov"],
    remarks: "DOB 15 Mar 1965",
  },
  {
    name: "Golden Star Shipping Ltd",
    type: "vessel",
    programs: ["IRAN", "SDGT"],
    aliases: ["GSS Ltd"],
    remarks: "IMO 9876543",
  },
  {
    name: "Maria Garcia",
    type: "individual",
    programs: ["SYRIA"],
    aliases: ["M. Garcia"],
    remarks: "DOB 22 Jul 1980",
  },
];

// ─── Fuzzy Matching ─────────────────────────────────────────────────────────

const DEFAULT_THRESHOLD = 0.85;

function normalise(input: string): string {
  return input.toLowerCase().replace(/[^a-z0-9\s]/g, "").trim();
}

function jaroWinkler(a: string, b: string): number {
  return JaroWinklerDistance(a, b);
}

function matchRecord(
  queryName: string,
  record: SdnRecord,
  threshold: number
): SanctionsMatch | null {
  const normQuery = normalise(queryName);
  const normTarget = normalise(record.name);

  if (normQuery === normTarget) {
    return {
      sdnName: record.name,
      sdnType: record.type,
      programs: record.programs,
      score: 1.0,
      matchType: "exact",
      aliases: record.aliases,
      remarks: record.remarks,
    };
  }

  const primaryScore = jaroWinkler(normQuery, normTarget);
  if (primaryScore >= threshold) {
    return {
      sdnName: record.name,
      sdnType: record.type,
      programs: record.programs,
      score: primaryScore,
      matchType: "fuzzy",
      aliases: record.aliases,
      remarks: record.remarks,
    };
  }

  for (const alias of record.aliases) {
    const aliasScore = jaroWinkler(normQuery, normalise(alias));
    if (aliasScore >= threshold) {
      return {
        sdnName: record.name,
        sdnType: record.type,
        programs: record.programs,
        score: aliasScore,
        matchType: "alias",
        aliases: record.aliases,
        remarks: record.remarks,
      };
    }
  }

  return null;
}

// ─── Public API ─────────────────────────────────────────────────────────────

export class SanctionsService {
  private readonly records: SdnRecord[];
  private readonly defaultThreshold: number;

  constructor(records?: SdnRecord[], defaultThreshold = DEFAULT_THRESHOLD) {
    this.records = records ?? SDN_RECORDS;
    this.defaultThreshold = defaultThreshold;
  }

  screen(query: SanctionsQuery): SanctionsResult {
    const start = performance.now();
    const threshold = query.threshold ?? this.defaultThreshold;

    const matches: SanctionsMatch[] = [];

    for (const record of this.records) {
      if (record.type !== query.type) continue;
      const match = matchRecord(query.name, record, threshold);
      if (match) matches.push(match);
    }

    matches.sort((a, b) => b.score - a.score);

    const elapsed = performance.now() - start;

    return {
      query,
      matched: matches.length > 0,
      matches,
      screenedAt: new Date().toISOString(),
      sdnListVersion: SDN_LIST_VERSION,
      processingTimeMs: Math.round(elapsed * 100) / 100,
    };
  }
}

export const sanctionsService = new SanctionsService();
