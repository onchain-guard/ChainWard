import type { Detector } from "../detector.ts";
import type { Signal } from "../types.ts";
import type { InjectionClassifier } from "../classifier.ts";

// Wraps an InjectionClassifier. Preserves the original coupling: a high probability that
// coincides with a structural shape-anomaly (from prior signals) is a hard tell.
export function classifierDetector(clf: InjectionClassifier, threshold = 0.8): Detector {
  return {
    id: "l2b.classifier",
    layer: "classifier",
    async detect({ normalized, kind, prior }): Promise<Signal[]> {
      const p = await clf.score(normalized, kind);
      if (p < 0.4) return [];
      const shapeAnomaly = prior.some((s) => s.code === "MIXED_SCRIPT" || s.code.startsWith("INVISIBLE_"));
      return [{
        layer: "classifier",
        code: "INJECTION_INTENT",
        detail: `${clf.name} scores injection-intent p=${p}${p >= threshold ? " (high)" : ""}.`,
        weight: p >= threshold ? 0.7 : 0.4,
        evidence: `p=${p}`,
        hard: p >= threshold && shapeAnomaly,
      }];
    },
  };
}
