declare module "cloudflare:workers" {
  import type { CellContext } from "./credential-do.js";

  export abstract class DurableObject<Env extends object = object> {
    protected readonly ctx: CellContext;
    protected readonly env: Env;
    constructor(ctx: CellContext, env: Env);
  }
}
