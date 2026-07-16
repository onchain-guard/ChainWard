import type { Detector } from "../detector.ts";
import { analyzeStructure } from "../normalize.ts";

// L1 runs on RAW text (before invisibles are stripped).
export const structuralDetector: Detector = {
  id: "l1.structural",
  layer: "structural",
  detect: ({ raw }) => analyzeStructure(raw),
};
