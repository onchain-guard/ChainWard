// Core type contracts for ChainWard.
// These are the stable interfaces every layer and adapter speaks. Swapping a mock
// adapter for a real one (RPC / GoPlus / Prompt Guard) never touches these.

export type Severity = "CLEAN" | "SUSPICIOUS" | "MALICIOUS";

/** Which on-chain field a piece of text came from. Field kind carries a *shape prior*:
 *  a token symbol is expected to be a short ticker, so a full imperative sentence in it
 *  is anomalous regardless of content. The scanner uses this. */
export type FieldKind =
  | "token_name"
  | "token_symbol"
  | "nft_name"
  | "nft_description"
  | "tx_memo"
  | "contract_comment"
  | "ens_text"
  | "agent_context"; // freeform text of an assembled prompt/message (proxy & guard() path)

export type Layer = "structural" | "pattern" | "classifier" | "deception" | "differential";

/** Consuming environment(s) the scanned data will flow into. Decides which parser-
 *  differential interpreters run (see core/interpreters). */
export type TargetContext = "llm-chat" | "markdown-ui" | "plaintext";

export interface Signal {
  layer: Layer;
  /** machine-stable code, e.g. "INVISIBLE_TAG_CHAR" */
  code: string;
  /** human explanation */
  detail: string;
  /** contribution to the field score, 0..1 */
  weight: number;
  /** the offending substring / codepoint, if any */
  evidence?: string;
  /** if true, this signal alone forces MALICIOUS (a hard structural tell) */
  hard?: boolean;
}

export interface FieldScan {
  kind: FieldKind;
  raw: string;
  normalized: string;
  /** model-safe rendering of this field (invisible chars stripped, homoglyphs folded,
   *  and — for non-CLEAN fields — wrapped as untrusted data). Give THIS to the LLM. */
  sanitized: string;
  severity: Severity;
  /** fused score 0..1 */
  score: number;
  signals: Signal[];
}

export interface ScanTarget {
  kind: "token" | "nft" | "tx";
  chain: string;
  address?: string;
  tokenId?: string;
  txHash?: string;
}

export interface ScanReport {
  target: ScanTarget;
  /** worst severity across all fields */
  severity: Severity;
  fields: FieldScan[];
  summary: string;
}

/** Expected length ceiling per field kind — used as a shape prior. */
export const FIELD_SHAPE: Record<FieldKind, { maxLabelLen: number; freeform: boolean }> = {
  token_symbol: { maxLabelLen: 12, freeform: false },
  token_name: { maxLabelLen: 40, freeform: false },
  nft_name: { maxLabelLen: 80, freeform: false },
  nft_description: { maxLabelLen: 2000, freeform: true },
  tx_memo: { maxLabelLen: 200, freeform: true },
  contract_comment: { maxLabelLen: 4000, freeform: true },
  ens_text: { maxLabelLen: 300, freeform: true },
  agent_context: { maxLabelLen: 100000, freeform: true },
};
