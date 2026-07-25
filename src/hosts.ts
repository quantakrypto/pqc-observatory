import { readFileSync } from "node:fs";

/** One panel entry: the domain plus the category id that explains why it is measured. */
export type SeedHost = {
  domain: string;
  category: string;
  /** 1-based position in the panel file (used only to bucket rollups). */
  rank: number;
};

/** Load and validate panel.json into ranked seed hosts. */
export function loadPanel(path: string): SeedHost[] {
  const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (!Array.isArray(raw)) throw new Error(`${path}: expected a JSON array`);
  const seen = new Set<string>();
  const out: SeedHost[] = [];
  raw.forEach((entry, i) => {
    const e = entry as { domain?: unknown; category?: unknown };
    const domain = typeof e.domain === "string" ? e.domain.trim().toLowerCase() : "";
    const category = typeof e.category === "string" ? e.category.trim() : "";
    if (!domain) throw new Error(`${path}: entry ${i} has no domain`);
    if (!/^[a-z0-9.-]+$/.test(domain)) throw new Error(`${path}: entry ${i} has an invalid domain "${domain}"`);
    if (seen.has(domain)) return; // ignore duplicates
    seen.add(domain);
    out.push({ domain, category: category || "consumer", rank: out.length + 1 });
  });
  return out;
}

/** Load optout.txt: one domain per line, `#` comments and blanks ignored. */
export function loadOptOut(path: string): string[] {
  let text = "";
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  return text
    .split("\n")
    .map((l) => l.replace(/#.*/, "").trim().toLowerCase())
    .filter(Boolean);
}
