// Serialize native proof generation within one Desktop instance.

let proofQueue: Promise<void> = Promise.resolve();

export type PersonaProofStatus = Readonly<{
  state: 'idle' | 'running' | 'completed' | 'failed';
  operation?: string;
  completedAt?: number;
  error?: string;
}>;

let proofStatus: PersonaProofStatus = { state: 'idle' };

export function getPersonaProofStatus(): PersonaProofStatus {
  return proofStatus;
}

export function withPersonaProofLock<T>(
  operation: string,
  produce: () => T
): Promise<T> {
  const run = () => {
    proofStatus = { state: 'running', operation };
    try {
      const result = produce();
      if (result === undefined) {
        proofStatus = {
          state: 'failed',
          operation,
          completedAt: Date.now(),
          error: 'proof operation returned no record',
        };
        return result;
      }
      proofStatus = {
        state: 'completed',
        operation,
        completedAt: Date.now(),
      };
      return result;
    } catch (error) {
      proofStatus = {
        state: 'failed',
        operation,
        completedAt: Date.now(),
        error: String(error),
      };
      throw error;
    }
  };
  const result = proofQueue.then(run, run);
  proofQueue = result.then(
    () => undefined,
    () => undefined
  );
  return result;
}
