/** Minimal shape of a CashScript artifact this project consumes. */
export interface Artifact {
  contractName: string;
  bytecode: string;
  constructorInputs: readonly { name: string; type: string }[];
  abi: readonly { name: string; inputs: readonly { name: string; type: string }[] }[];
}
