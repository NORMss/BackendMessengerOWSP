// False-positive classifier: logistic-regression inference over context
// features. Pure TypeScript, no native dependencies, so it runs identically
// inside VS Code and in the CI CLI.

import { MODEL } from './model';
import { extractFeatures, FeatureContext } from './features';

export function sigmoid(z: number): number {
  return 1 / (1 + Math.exp(-z));
}

/** Dot product of features and weights → probability via sigmoid. */
export function predictProba(features: number[], weights: number[] = MODEL.weights): number {
  let z = 0;
  const n = Math.min(features.length, weights.length);
  for (let i = 0; i < n; i++) {
    z += features[i] * weights[i];
  }
  return sigmoid(z);
}

export interface Classification {
  /** Probability that the finding is a genuine vulnerability (0..1). */
  confidence: number;
  /** True if confidence ≥ model threshold. */
  isVulnerable: boolean;
}

export function classify(ctx: FeatureContext, threshold: number = MODEL.threshold): Classification {
  const features = extractFeatures(ctx);
  const confidence = predictProba(features);
  return { confidence, isVulnerable: confidence >= threshold };
}
