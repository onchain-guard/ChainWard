// Detector plugin contract + registry (design §5.3).
// A detector implements one detection concern and returns Signals. The scanner runs all
// registered detectors in registration order, threading accumulated `prior` signals so a
// later detector (e.g. the classifier) can consult earlier-layer findings.

import type { FieldKind, Layer, Signal } from "./types.ts";
import type { FieldContext } from "./scanner.ts";

export interface DetectInput {
  raw: string;
  normalized: string;
  kind: FieldKind;
  ctx: FieldContext;
  /** signals produced by earlier detectors in this scan (read-only) */
  prior: Signal[];
}

export interface Detector {
  readonly id: string;     // stable, e.g. "l1.structural"
  readonly layer: Layer;
  detect(input: DetectInput): Signal[] | Promise<Signal[]>;
}

export class DetectorRegistry {
  private detectors: Detector[] = [];
  use(d: Detector): this {
    this.detectors.push(d);
    return this;
  }
  list(): readonly Detector[] {
    return this.detectors;
  }
}
