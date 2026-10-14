/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
import type { Detector } from "../detector.ts";
import { analyzePatterns } from "../patterns.ts";

// L2a runs on NORMALIZED text (homoglyphs folded, invisibles stripped).
export const patternDetector: Detector = {
  id: "l2a.pattern",
  layer: "pattern",
  detect: ({ normalized }) => analyzePatterns(normalized),
};
