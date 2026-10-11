/** Signed evidence uses the deployed authority's RFC 9964 issuer and existing KMS key. */
import { constants } from "node:fs";
import { randomUUID, createHash } from "node:crypto";
import { mkdir, lstat, open, rename, unlink, readdir } from "node:fs/promises";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseDiagnostic, type Measurement } from "./probe.js";


async function readBounded(path: string, limit: number): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > limit) throw new Error("invalid bounded file");
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length <= limit) {
      const result = await handle.read(buffer, length, buffer.length-length, null);
      if (!result.bytesRead) break;
      length += result.bytesRead;
      if (length > limit) throw new Error("file too large");
    }
    return buffer.subarray(0,length);
  } finally { await handle.close(); }
}

export type SignedMeasurement = {
  version: 1;
  subject: string;
  token: string;
  transcript: string;
  transcriptSha256: string;
};
export type AuthorityIssue = (options: Record<string, unknown>) => Promise<string>;
export interface ExportOptions {
  outputDirectory: string;
  authorityDirectory: string;
  onlineKeyRef: string;
  keyId: string;
  issuer: string;
  audience: string;
  ledgerPath: string;
  allowedSubjects: string[];
  /** Optional independently supplied sha256:<hex> manifest digests by subject. */
  snapshotBindings?: Record<string, string>;
  ttlSeconds?: number;
}

export async function createExporter(options: ExportOptions, dependencies?: { issue: AuthorityIssue; signer: unknown }): Promise<{
  exportMeasurement: (measurement: Measurement) => Promise<SignedMeasurement>;
}> {
  for (const name of ["outputDirectory", "authorityDirectory", "onlineKeyRef", "keyId", "issuer", "audience", "ledgerPath"] as const) {
    if (!options[name] || typeof options[name] !== "string") throw new Error(`missing exporter ${name}`);
  }
  if (!Array.isArray(options.allowedSubjects) || !options.allowedSubjects.length ||
      options.allowedSubjects.some((s) => typeof s !== "string" || !s.startsWith("https://")))
    throw new Error("explicit subject signing policy required");
  const ttl = options.ttlSeconds ?? 3600;
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 3600) throw new Error("invalid exporter TTL");
  const output = resolve(options.outputDirectory);
  await mkdir(output, { recursive: true, mode: 0o700 });
  const directory = await lstat(output);
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0)
    throw new Error("export directory must be private and not a symlink");
  let issue: AuthorityIssue, signer: unknown;
  if (dependencies) ({ issue, signer } = dependencies);
  else {
    const authority = resolve(options.authorityDirectory);
    const issuerModule = await import(pathToFileURL(join(authority, "src", "observation.mjs")).href);
    const signerModule = await import(pathToFileURL(join(authority, "src", "signer.mjs")).href);
    issue = issuerModule.issueObservation as AuthorityIssue;
    signer = await signerModule.getSigner("aws");
  }
  return { async exportMeasurement(measurement) {
    if (!measurement.certificateValidated || !measurement.observation || !measurement.transcript)
      throw new Error("only fresh validated measurements can be exported");
    const observation = measurement.observation;
    const subject = `https://${observation.endpoint.host}${observation.endpoint.port === 443 ? "" : `:${observation.endpoint.port}`}`;
    if (!options.allowedSubjects.includes(subject)) throw new Error("subject not authorized for signing");
    if (Buffer.byteLength(measurement.transcript) > 65536) throw new Error("transcript too large");
    const parsed = parseDiagnostic(measurement.transcript);
    if (!parsed.validated || !observation.probe.groups.includes(parsed.group ?? "")) throw new Error("invalid measurement diagnostics");
    const now = new Date();
    const seconds = Math.floor(now.getTime()/1000);
    if (!Number.isFinite(Date.parse(observation.observedAt)) || Date.parse(observation.observedAt) > now.getTime()
        || now.getTime()-Date.parse(observation.observedAt) > 3600000) throw new Error("measurement export must be within one hour");
    if (createHash("sha256").update(measurement.transcript, "utf8").digest("hex") !== observation.transcriptSha256)
      throw new Error("measurement transcript mismatch");
    const claims: Record<string, unknown> = { iss: options.issuer, sub: subject, aud: options.audience,
      iat: seconds, exp: seconds+ttl, jti: randomUUID(), purpose: "pqc-observation", observation };
    const snapshotDigest = options.snapshotBindings?.[subject];
    if (snapshotDigest !== undefined) {
      if (!/^sha256:[a-f0-9]{64}$/.test(snapshotDigest)) throw new Error("invalid configured snapshot digest");
      claims.snapshotDigest = snapshotDigest;
    }
    const token = await issue({ signer, onlineKeyRef: options.onlineKeyRef, keyId: options.keyId,
      ledgerPath: options.ledgerPath, claims,
      policy: { issuer: options.issuer, audiences: [options.audience], subjects: options.allowedSubjects, maxLifetimeSeconds: ttl }, now: seconds });
    const bundle: SignedMeasurement = { version: 1, subject, token, transcript: measurement.transcript,
      transcriptSha256: observation.transcriptSha256 };
    // Unique names preserve signed evidence; no historical row is silently upgraded.
    const name = `${createHash("sha256").update(subject).digest("hex").slice(0, 24)}-${claims.jti as string}.json`;
    const target = join(output, name), temporary = `${target}.tmp`;
    const handle = await open(temporary, "wx", 0o600);
    try { await handle.writeFile(JSON.stringify(bundle)+"\n"); await handle.sync(); }
    finally { await handle.close(); }
    try { await rename(temporary, target); }
    catch (error) { await unlink(temporary).catch(() => {}); throw error; }
    return bundle;
  } };
}

/** Environment contains paths/key references, never copies of private key material. */
export async function exporterFromEnvironment(): Promise<Awaited<ReturnType<typeof createExporter>> | null> {
  if (!process.env.OBS_SIGNED_OUTPUT) return null;
  if (!process.env.OBS_SIGNING_SUBJECTS) throw new Error("OBS_SIGNING_SUBJECTS policy file required");
  const subjectsRaw = (await readBounded(process.env.OBS_SIGNING_SUBJECTS, 1048576)).toString("utf8");
  if (Buffer.byteLength(subjectsRaw) > 1048576) throw new Error("subject policy too large");
  const allowedSubjects = JSON.parse(subjectsRaw) as string[];
  let snapshotBindings: Record<string, string> | undefined;
  if (process.env.OBS_SNAPSHOT_BINDINGS) {
    const raw = (await readBounded(process.env.OBS_SNAPSHOT_BINDINGS, 1048576)).toString("utf8");
    if (Buffer.byteLength(raw) > 1048576) throw new Error("snapshot binding map too large");
    snapshotBindings = JSON.parse(raw) as Record<string, string>;
    if (!snapshotBindings || Array.isArray(snapshotBindings) || typeof snapshotBindings !== "object"
        || Object.values(snapshotBindings).some((path) => typeof path !== "string")) throw new Error("invalid snapshot binding map");
  }
  return createExporter({ outputDirectory: process.env.OBS_SIGNED_OUTPUT,
    authorityDirectory: process.env.OBS_AUTHORITY_DIR ?? "", onlineKeyRef: process.env.QK_ONLINE_KEY_REF ?? "",
    keyId: process.env.QK_ONLINE_KEY_ID ?? "", issuer: process.env.OBS_ISSUER ?? "",
    audience: process.env.OBS_AUDIENCE ?? "", ledgerPath: process.env.OBS_LEDGER_PATH ?? "", allowedSubjects, snapshotBindings });
}

/** Unsigned fresh collector records for transfer to the existing GitHub KMS job.
 * A record is not authenticated until the independently authorized issuer signs.
 * The transfer and collector host must be authenticated by deployment policy.
 */
export async function collectRecord(directory: string, measurement: Measurement): Promise<string> {
  if (!measurement.certificateValidated || !measurement.observation || !measurement.transcript)
    throw new Error("unvalidated observations cannot be collected for signing");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0)
    throw new Error("collection directory must be private and not a symlink");
  const id = createHash("sha256").update(JSON.stringify(measurement.observation)).digest("hex");
  const target = join(directory, `${id}.json`);
  const handle = await open(target, "wx", 0o600);
  try { await handle.writeFile(JSON.stringify(measurement)+"\n"); await handle.sync(); }
  catch (error) { await unlink(target).catch(() => {}); throw error; }
  finally { await handle.close(); }
  return target;
}

export async function exportFreshRecords(inputDirectory: string): Promise<number> {
  const exporter = await exporterFromEnvironment();
  if (!exporter) throw new Error("OBS_SIGNED_OUTPUT and authority policy are required");
  const names = (await readdir(inputDirectory)).filter((name) => /^[a-f0-9]{64}\.json$/.test(name)).sort();
  if (names.length > 10000) throw new Error("too many collector records");
  let count = 0;
  for (const name of names) {
    const source = join(inputDirectory, name);
    const metadata = await lstat(source);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 131072)
      throw new Error("invalid collector record file");
    const bytes = await readBounded(source, 131072);
    if (bytes.length > 131072) throw new Error("collector record too large");
    const measurement = JSON.parse(bytes.toString("utf8")) as Measurement;
    if (createHash("sha256").update(JSON.stringify(measurement.observation)).digest("hex")+".json" !== name)
      throw new Error("collector record identity mismatch");
    await exporter.exportMeasurement(measurement);
    count++;
  }
  return count;
}
