import worker from "../../packages/worker/src/index.ts";

export {
  Credential,
  Registry,
  Replay,
  Grants,
} from "../../packages/worker/src/index.ts";

declare const __BUNDLE_COMMIT__: string;

declare const __BUNDLE_VERSION__: string;

export default {
  fetch(
    request: Request,
    env: Parameters<typeof worker.fetch>[1]
  ): Response | Promise<Response> {
    const url = new URL(request.url);

    return request.method === "GET" &&
      url.pathname === "/.well-known/rat-king/version"
      ? Response.json({
          commit: __BUNDLE_COMMIT__,
          version: __BUNDLE_VERSION__,
        })
      : worker.fetch(request, env);
  },
};
