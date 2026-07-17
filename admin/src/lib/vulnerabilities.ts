import type { Vulnerability } from "@/lib/contracts";

function findingKey(vulnerability: Vulnerability): string {
  return [
    vulnerability.source,
    vulnerability.vuln_id,
    vulnerability.affected_asset_id,
    vulnerability.parent_asset_id ?? "",
    vulnerability.evidence ?? "",
  ].join("\u0000");
}

/** Merge exact scanner/derived copies without collapsing distinct evidence locations. */
export function mergeVulnerabilities(
  ...groups: (Vulnerability[] | null | undefined)[]
): Vulnerability[] {
  const merged = new Map<string, Vulnerability>();
  for (const group of groups) {
    for (const vulnerability of group ?? []) {
      const key = findingKey(vulnerability);
      const current = merged.get(key);
      if (!current) {
        merged.set(key, vulnerability);
      } else {
        const references = [...new Set([...(current.references ?? []), ...(vulnerability.references ?? [])])];
        merged.set(key, {
          ...current,
          ...vulnerability,
          cvss_score: vulnerability.cvss_score ?? current.cvss_score,
          evidence: vulnerability.evidence ?? current.evidence,
          references: references.length > 0 ? references : undefined,
        });
      }
    }
  }
  return [...merged.values()];
}
