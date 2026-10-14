/* Copyright 2026 0xShield. All Rights Reserved.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
import type { Detector } from "../detector.ts";
import { runInterpreters } from "../interpreters/index.ts";

// L4 runs on NORMALIZED text for the declared consuming environment(s).
export const differentialDetector: Detector = {
  id: "l4.differential",
  layer: "differential",
  detect: ({ normalized, ctx }) =>
    ctx.targetContexts?.length ? runInterpreters(normalized, ctx.targetContexts, ctx.model) : [],
};
