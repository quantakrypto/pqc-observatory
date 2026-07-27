/**
 * The panel is grouped into categories. Each category carries a short reason it
 * is on the panel and a note on how strong a signal it is for web-wide quantum
 * readiness. The worker resolves a host's category to these fields and stores
 * them, so the public site can explain why every host is measured.
 */
export type Category = {
  id: string;
  label: string;
  /** Why hosts of this kind are on the panel. */
  reason: string;
  /** How strong a signal this category is for web-wide readiness. */
  relevance: string;
};

export const CATEGORIES: Record<string, Category> = {
  cdn: {
    id: "cdn",
    label: "CDN / edge",
    reason:
      "Content delivery networks terminate TLS for a large share of the web, so their defaults propagate hybrid key exchange to millions of downstream sites at once.",
    relevance: "Bellwether",
  },
  cloud: {
    id: "cloud",
    label: "Cloud / SaaS",
    reason: "Cloud and platform providers set the cryptographic defaults for everything built on top of them.",
    relevance: "High",
  },
  security: {
    id: "security",
    label: "Security / PKI",
    reason:
      "Security, identity, and certificate vendors are expected to lead on cryptographic hygiene; a laggard here is a notable signal.",
    relevance: "High",
  },
  messaging: {
    id: "messaging",
    label: "Messaging / privacy",
    reason:
      "Privacy-focused messaging and email carry the strongest harvest-now-decrypt-later incentive, so they tend to adopt post-quantum protection earliest.",
    relevance: "Leading indicator",
  },
  payments: {
    id: "payments",
    label: "Payments",
    reason: "Payment providers sit under the strongest compliance pressure (PCI DSS) to keep cryptography current.",
    relevance: "High",
  },
  dev: {
    id: "dev",
    label: "Developer platform",
    reason: "Developer platforms and package registries sit in the software supply chain, so their posture affects downstream builds.",
    relevance: "Medium-high",
  },
  measurement: {
    id: "measurement",
    label: "Measurement / research",
    reason: "Services that themselves measure the ecosystem: useful reference points and often early adopters.",
    relevance: "Reference",
  },
  consumer: {
    id: "consumer",
    label: "Consumer web",
    reason: "High-traffic consumer sites represent what a typical user actually connects to.",
    relevance: "Baseline",
  },
  media: {
    id: "media",
    label: "News / media",
    reason: "Large media properties, run by many independent operators, give a broad-web baseline.",
    relevance: "Baseline",
  },
  government: {
    id: "government",
    label: "Government / public sector",
    reason:
      "Governments write the migration mandates the rest of the ecosystem follows (CNSA 2.0, NIS2, and national PQC deadlines), yet the public sector typically moves slower than the tech industry. Whether their own public front doors have migrated is therefore a distinct and telling signal, separate from the vendors they regulate.",
    relevance: "Mandate-setter / baseline",
  },
};

export function resolveCategory(id: string): Category {
  return CATEGORIES[id] ?? { id, label: id, reason: "", relevance: "" };
}
