import type { Detector } from "../detector.ts";
import { analyzePatterns } from "../patterns.ts";

// L2a runs on NORMALIZED text (homoglyphs folded, invisibles stripped).
export const patternDetector: Detector = {
  id: "l2a.pattern",
  layer: "pattern",
  detect: ({ normalized }) => analyzePatterns(normalized),
};
