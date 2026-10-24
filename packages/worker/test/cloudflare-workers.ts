import type { CellContext } from "../src/credential-do.js";

export abstract class DurableObject<Env extends object = object> {
  protected readonly ctx: CellContext;
  protected readonly env: Env;
  constructor(ctx: CellContext, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
