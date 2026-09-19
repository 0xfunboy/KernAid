import https from "node:https";
import { performance } from "node:perf_hooks";
import {
  calculateCost,
  createAssistantMessageEventStream,
} from "@earendil-works/pi-ai";

export const GEMROUTER_API = "kernaid-gemrouter-nonstream";
export const GEMROUTER_LIMITS = Object.freeze({
  connectTimeoutMs: 10_000,
  timeoutMs: 120_000,
  maxBytes: 512 * 1024,
  concurrency: 2,
  requestsPerMinute: 30,
});

class TransportError extends Error {}
const failure = (message) => new TransportError(message);

function endpoint(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw failure("Invalid Gemrouter endpoint.");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw failure(
      "Use an HTTPS Gemrouter endpoint without credentials or query parameters.",
    );
  return url.href.replace(/\/+$/, "");
}

// A rolling, process-wide budget shared by /models and /chat/completions.
// Fail locally instead of queuing, retrying, or accumulating unbounded work.
export function createGemrouterLimiter({ now = () => performance.now() } = {}) {
  let active = 0;
  let starts = [];
  return {
    acquire() {
      const time = now();
      starts = starts.filter((start) => time - start < 60_000);
      if (active >= GEMROUTER_LIMITS.concurrency)
        throw failure("Gemrouter concurrency limit reached. Try again later.");
      if (starts.length >= GEMROUTER_LIMITS.requestsPerMinute)
        throw failure("Gemrouter request limit reached. Try again later.");
      starts.push(time);
      active++;
      let released = false;
      return () => {
        if (!released) active--;
        released = true;
      };
    },
  };
}
const appLimiter = createGemrouterLimiter();

function boundedTimeout(value, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum)
    throw failure("Invalid Gemrouter timeout.");
  return value;
}

/**
 * Pin a transport to the endpoint selected with its credential. The optional
 * request/limiter and shorter deadlines support offline, disposable tests.
 * No global fetch, proxy credentials, OAuth, cookies, or SDK retries are used.
 */
export function createGemrouterTransport({
  baseUrl,
  request = https.request,
  limiter = appLimiter,
  connectTimeoutMs = GEMROUTER_LIMITS.connectTimeoutMs,
  timeoutMs = GEMROUTER_LIMITS.timeoutMs,
}) {
  const selectedEndpoint = endpoint(baseUrl);
  boundedTimeout(connectTimeoutMs, GEMROUTER_LIMITS.connectTimeoutMs);
  boundedTimeout(timeoutMs, GEMROUTER_LIMITS.timeoutMs);

  async function requestJson(
    route,
    { apiKey, signal, body, requestTimeoutMs = timeoutMs } = {},
  ) {
    if (!["/models", "/chat/completions"].includes(route))
      throw failure("Unsupported Gemrouter route.");
    if (
      typeof apiKey !== "string" ||
      !apiKey.trim() ||
      apiKey.length > 4096 ||
      /[^\x21-\x7e]/.test(apiKey)
    )
      throw failure("Enter a valid API key for this endpoint.");
    if (signal?.aborted) throw failure("Gemrouter request aborted.");
    const deadline = boundedTimeout(requestTimeoutMs, timeoutMs);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (
      payload !== undefined &&
      Buffer.byteLength(payload) > GEMROUTER_LIMITS.maxBytes
    )
      throw failure("Gemrouter request too large.");
    const release = limiter.acquire();
    try {
      return await new Promise((resolve, reject) => {
        let req;
        let response;
        let settled = false;
        let connectionTimer;
        let requestTimer;
        const finish = (error, value) => {
          if (settled) return;
          settled = true;
          clearTimeout(connectionTimer);
          clearTimeout(requestTimer);
          signal?.removeEventListener("abort", abort);
          // Destroy on failure so a stalled or oversized body cannot keep using
          // a connection after its concurrency permit is released.
          if (error) {
            response?.destroy();
            req?.destroy();
            reject(error);
          } else resolve(value);
        };
        const abort = () => finish(failure("Gemrouter request aborted."));
        connectionTimer = setTimeout(
          () => finish(failure("Gemrouter connection timed out.")),
          connectTimeoutMs,
        );
        // This is an aggregate deadline, not a socket-idle timeout: it includes
        // DNS, TCP, TLS, request headers, and the complete JSON response body.
        requestTimer = setTimeout(
          () => finish(failure("Gemrouter request timed out.")),
          deadline,
        );
        signal?.addEventListener("abort", abort, { once: true });
        if (signal?.aborted) return abort();
        try {
          req = request(
            new URL(selectedEndpoint + route),
            {
              method: body === undefined ? "GET" : "POST",
              agent: false,
              headers: {
                Authorization: `Bearer ${apiKey}`,
                "x-gemrouter-backend": "gemini-api",
                Accept: "application/json",
                ...(payload === undefined
                  ? {}
                  : {
                      "Content-Type": "application/json",
                      "Content-Length": Buffer.byteLength(payload),
                    }),
              },
            },
            (incoming) => {
              response = incoming;
              if (settled) return incoming.destroy();
              clearTimeout(connectionTimer);
              incoming.on("error", () =>
                finish(failure("Gemrouter response failed.")),
              );
              incoming.on("aborted", () =>
                finish(failure("Gemrouter response interrupted.")),
              );
              // node:https never follows Location, including cross-origin redirects.
              if (
                incoming.statusCode < 200 ||
                incoming.statusCode >= 300 ||
                !incoming.statusCode
              )
                return finish(
                  failure(
                    `Gemrouter returned HTTP ${incoming.statusCode || 0}.`,
                  ),
                );
              if (
                Number(incoming.headers["content-length"]) >
                GEMROUTER_LIMITS.maxBytes
              )
                return finish(failure("Gemrouter response too large."));
              let size = 0;
              const chunks = [];
              incoming.on("data", (chunk) => {
                if (settled) return;
                size += chunk.length;
                if (size > GEMROUTER_LIMITS.maxBytes)
                  return finish(failure("Gemrouter response too large."));
                chunks.push(chunk);
              });
              incoming.on("end", () => {
                if (settled) return;
                try {
                  finish(
                    undefined,
                    JSON.parse(Buffer.concat(chunks).toString("utf8")),
                  );
                } catch {
                  finish(failure("Gemrouter returned invalid JSON."));
                }
              });
              incoming.on("close", () => {
                if (!settled)
                  finish(failure("Gemrouter response interrupted."));
              });
            },
          );
          req.on("socket", (socket) => {
            socket.once("secureConnect", () => clearTimeout(connectionTimer));
          });
          req.on("error", () =>
            finish(failure("Gemrouter connection failed.")),
          );
          req.end(payload);
        } catch {
          finish(failure("Gemrouter connection failed."));
        }
      });
    } finally {
      release();
    }
  }

  function streamSimple(model, context, options = {}) {
    const stream = createAssistantMessageEventStream();
    const output = {
      role: "assistant",
      content: [],
      api: model.api,
      provider: model.provider,
      model: model.id,
      usage: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "stop",
      timestamp: Date.now(),
    };
    void (async () => {
      stream.push({ type: "start", partial: output });
      try {
        if (
          model.api !== GEMROUTER_API ||
          endpoint(model.baseUrl) !== selectedEndpoint
        )
          throw failure(
            "Gemrouter endpoint changed. Reconfigure its credential.",
          );
        if (
          typeof model.id !== "string" ||
          !model.id ||
          model.id.length > 160 ||
          /[\r\n\0]/.test(model.id)
        )
          throw failure("Choose a valid Gemrouter model.");
        const payload = {
          model: model.id,
          messages: textMessages(context),
          stream: false,
          max_tokens: Math.min(
            options.maxTokens ?? model.maxTokens,
            model.maxTokens,
          ),
        };
        if (!Number.isSafeInteger(payload.max_tokens) || payload.max_tokens < 1)
          throw failure("Invalid Gemrouter output limit.");
        if (options.temperature !== undefined) {
          if (
            !Number.isFinite(options.temperature) ||
            options.temperature < 0 ||
            options.temperature > 2
          )
            throw failure("Invalid Gemrouter temperature.");
          payload.temperature = options.temperature;
        }
        // Deliberately do not merge headers, metadata, thinking, tools, store,
        // stream_options, or onPayload mutations into this verified protocol.
        const data = await requestJson("/chat/completions", {
          apiKey: options.apiKey,
          signal: options.signal,
          requestTimeoutMs:
            options.timeoutMs === undefined
              ? timeoutMs
              : Math.min(options.timeoutMs, timeoutMs),
          body: payload,
        });
        if (options.signal?.aborted)
          throw failure("Gemrouter request aborted.");
        const choice = data?.choices?.[0];
        if (
          !choice ||
          !["stop", "length"].includes(choice.finish_reason) ||
          choice.message?.role !== "assistant" ||
          typeof choice.message.content !== "string" ||
          !choice.message.content.trim() ||
          choice.message.tool_calls?.length ||
          choice.message.function_call
        )
          throw failure("Gemrouter returned an unsupported or empty answer.");
        output.stopReason = choice.finish_reason;
        const count = (value) =>
          Number.isSafeInteger(value) && value >= 0 ? value : 0;
        const input = count(data.usage?.prompt_tokens);
        output.usage.cacheRead = Math.min(
          input,
          count(data.usage?.prompt_tokens_details?.cached_tokens),
        );
        output.usage.input = input - output.usage.cacheRead;
        output.usage.output = count(data.usage?.completion_tokens);
        output.usage.totalTokens = input + output.usage.output;
        calculateCost(model, output.usage);
        output.content.push({ type: "text", text: "" });
        stream.push({ type: "text_start", contentIndex: 0, partial: output });
        output.content[0].text = choice.message.content;
        stream.push({
          type: "text_delta",
          contentIndex: 0,
          delta: choice.message.content,
          partial: output,
        });
        stream.push({
          type: "text_end",
          contentIndex: 0,
          content: choice.message.content,
          partial: output,
        });
        stream.push({
          type: "done",
          reason: output.stopReason,
          message: output,
        });
      } catch (error) {
        output.stopReason = options.signal?.aborted ? "aborted" : "error";
        output.errorMessage =
          error instanceof TransportError
            ? error.message
            : "Gemrouter request failed.";
        stream.push({
          type: "error",
          reason: output.stopReason,
          error: output,
        });
      } finally {
        stream.end();
      }
    })();
    return stream;
  }

  return Object.freeze({
    streamSimple,
    models: ({ apiKey, signal } = {}) =>
      requestJson("/models", { apiKey, signal }),
  });
}

function textMessages(context) {
  if (!Array.isArray(context?.messages) || context.tools?.length)
    throw failure("Gemrouter supports text conversation only.");
  const messages = [];
  if (context.systemPrompt) {
    if (typeof context.systemPrompt !== "string")
      throw failure("Invalid Gemrouter system prompt.");
    messages.push({ role: "system", content: context.systemPrompt });
  }
  for (const message of context.messages) {
    if (!["user", "assistant"].includes(message.role))
      throw failure("Gemrouter supports text conversation only.");
    if (
      message.role === "assistant" &&
      ["error", "aborted"].includes(message.stopReason)
    )
      continue;
    let content = message.content;
    if (Array.isArray(content)) {
      if (
        content.some(
          (block) => block.type !== "text" || typeof block.text !== "string",
        )
      )
        throw failure("Gemrouter supports text conversation only.");
      content = content.map((block) => block.text).join("\n");
    }
    if (typeof content !== "string")
      throw failure("Invalid Gemrouter message.");
    messages.push({ role: message.role, content });
  }
  if (!messages.some((message) => message.role === "user"))
    throw failure("Gemrouter requires a user message.");
  return messages;
}
