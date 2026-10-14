/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
import type { Detector } from "../detector.ts";
import { analyzeStructure } from "../normalize.ts";

// L1 runs on RAW text (before invisibles are stripped).
export const structuralDetector: Detector = {
  id: "l1.structural",
  layer: "structural",
  detect: ({ raw }) => analyzeStructure(raw),
};
