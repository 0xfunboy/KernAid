import React, { useEffect, useRef, useState } from "react";
import {
  assistantContextPreview,
  type AssistantInspectionContext,
} from "@kernaid/assistant-context";
import "./rescue-connection-wizard.css";

type Adapter = {
  name: string;
  type: "wifi" | "ethernet";
  state: string;
  connection: string;
};
type Wifi = { ssid: string; signal: string; security: string };
type Surface = { label: string; baseUrl: string; model: string };
type AssistantStatus = {
  defaults: { surfaces: Record<string, Surface> };
  config: Surface & { surface: string };
  credentialPresent: boolean;
  verified: boolean;
  modelDiscovery?: { state: string; models: string[] };
};
type Message = { role: "You" | "KernAid"; text: string };

async function call<T>(
  action: string,
  fields: Record<string, unknown> = {},
): Promise<T> {
  const response = await fetch("/api/rescue/assistant", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, ...fields }),
    cache: "no-store",
    signal: AbortSignal.timeout(140_000),
  });
  const data = await response.json();
  if (!response.ok || !data.ok)
    throw new Error(data.error || "Connection assistant unavailable.");
  return data as T;
}

export function RescueConnectionWizard({
  ready,
  onReady,
  context,
  contextKey,
}: {
  ready: boolean;
  onReady: () => void;
  context?: AssistantInspectionContext;
  contextKey: string;
}) {
  const [expanded, setExpanded] = useState(true);
  const [status, setStatus] = useState<AssistantStatus>();
  const [adapters, setAdapters] = useState<Adapter[]>([]);
  const [adapter, setAdapter] = useState("");
  const [networks, setNetworks] = useState<Wifi[]>([]);
  const [ssid, setSsid] = useState("");
  const [wifiPassword, setWifiPassword] = useState("");
  const [surface, setSurface] = useState("gemrouter");
  const [baseUrl, setBaseUrl] = useState("https://gemr.airewardrop.xyz/v1");
  const [model, setModel] = useState("gemini-3.8-flash");
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [verified, setVerified] = useState(false);
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [busy, setBusy] = useState("");
  const inFlight = useRef(false);
  const [error, setError] = useState("");
  const [contextConsent, setContextConsent] = useState<string>();
  const preview = context ? assistantContextPreview(context) : "";
  const contextBinding = JSON.stringify([
    contextKey,
    preview,
    surface,
    baseUrl,
    model,
  ]);
  const shareContext = Boolean(context && contextConsent === contextBinding);
  const latestContextKey = useRef(contextKey);
  const conversationId = useRef(crypto.randomUUID());
  useEffect(() => {
    latestContextKey.current = contextKey;
    conversationId.current = crypto.randomUUID();
    setContextConsent(undefined);
    setMessages([]);
  }, [contextKey]);
  async function work(label: string, fn: () => Promise<void>) {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(label);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Operation failed. Retry.");
    } finally {
      setBusy("");
      inFlight.current = false;
    }
  }
  async function refresh(restoreConfig = false) {
    const next = await call<AssistantStatus>("status");
    setStatus(next);
    if (restoreConfig) {
      setSurface(next.config.surface);
      setBaseUrl(next.config.baseUrl);
      setModel(next.config.model);
      setVerified(next.verified);
      setModels(next.modelDiscovery?.models || []);
    }
    const result = await call<{ adapters: Adapter[] }>("networks");
    setAdapters(result.adapters);
    setAdapter((current) =>
      result.adapters.some((item) => item.name === current)
        ? current
        : result.adapters.find((item) => item.state === "connected")?.name ||
          result.adapters[0]?.name ||
          "",
    );
  }
  useEffect(() => {
    void work("Finding network adapters…", () => refresh(true));
  }, []);
  function invalidate() {
    setVerified(false);
    setModels([]);
  }
  async function configure() {
    const next = await call<AssistantStatus>("configure", {
      surface,
      baseUrl,
      model,
      ...(apiKey ? { apiKey } : {}),
    });
    setStatus(next);
    setSurface(next.config.surface);
    setModels(next.modelDiscovery?.models || []);
    setBaseUrl(next.config.baseUrl);
    setModel(next.config.model);
    setContextConsent(undefined);
    setApiKey("");
    setVerified(false);
    setMessages([]);
  }
  function finish() {
    onReady();
    setExpanded(false);
  }
  const selectedAdapter = adapters.find((item) => item.name === adapter);
  return (
    <section
      className="connection-wizard"
      aria-label="KernAid connection assistant"
    >
      <div className="connection-heading">
        <div>
          <span className="connection-eyebrow">
            KERNAID · LET’S GET YOU CONNECTED
          </span>
          <h1>Your recovery starts here.</h1>
          <p>
            Connect to the internet, speak to your assistant, then choose the
            computer system to diagnose.
          </p>
        </div>
        {ready && (
          <button onClick={() => setExpanded(!expanded)}>
            {expanded
              ? "Hide assistant"
              : "Open assistant & connection settings"}
          </button>
        )}
      </div>
      {expanded && (
        <>
          <div className="connection-steps">
            <span>01 · Network</span>
            <span>02 · AI assistant</span>
            <span>03 · Diagnose</span>
          </div>
          <div className="connection-columns">
            <fieldset disabled={Boolean(busy)}>
              <legend>1. Connect this computer</legend>
              <label>
                Network adapter
                <select
                  value={adapter}
                  onChange={(e) => {
                    setAdapter(e.target.value);
                    setNetworks([]);
                    setSsid("");
                    setWifiPassword("");
                  }}
                >
                  {!adapters.length && (
                    <option value="">No adapter detected</option>
                  )}
                  {adapters.map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.type === "wifi" ? "Wi-Fi" : "Ethernet"} ·{" "}
                      {item.name} · {item.state}
                    </option>
                  ))}
                </select>
              </label>
              <button
                onClick={() => void work("Refreshing adapters…", refresh)}
              >
                Refresh adapters
              </button>
              {selectedAdapter?.type === "wifi" && (
                <>
                  <button
                    onClick={() =>
                      void work("Finding Wi-Fi networks…", async () => {
                        const result = await call<{ networks: Wifi[] }>(
                          "wifi",
                          { adapter },
                        );
                        setNetworks(result.networks);
                        setSsid(result.networks[0]?.ssid || "");
                      })
                    }
                  >
                    Find Wi-Fi networks
                  </button>
                  <label>
                    Wi-Fi network
                    <select
                      value={ssid}
                      onChange={(e) => setSsid(e.target.value)}
                    >
                      <option value="">Choose a network</option>
                      {networks.map((item) => (
                        <option key={item.ssid} value={item.ssid}>
                          {item.ssid} · {item.signal}% ·{" "}
                          {item.security || "Open"}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Wi-Fi password
                    <input
                      type="password"
                      autoComplete="off"
                      value={wifiPassword}
                      onChange={(e) => setWifiPassword(e.target.value)}
                    />
                  </label>
                </>
              )}
              <button
                className="connection-primary"
                disabled={
                  !adapter || (selectedAdapter?.type === "wifi" && !ssid)
                }
                onClick={() =>
                  void work("Connecting…", async () => {
                    try {
                      const result = await call<{ adapters: Adapter[] }>(
                        "connect",
                        { adapter, ssid, password: wifiPassword },
                      );
                      setAdapters(result.adapters);
                    } finally {
                      setWifiPassword("");
                    }
                  })
                }
              >
                Connect
              </button>
              <p>
                A connected cable may work automatically. You can continue
                offline if no connection is available.
              </p>
            </fieldset>
            <fieldset disabled={Boolean(busy)}>
              <legend>2. Choose your assistant</legend>
              <label>
                Provider
                <select
                  value={surface}
                  onChange={(e) => {
                    const id = e.target.value;
                    const next = status?.defaults.surfaces[id];
                    setSurface(id);
                    setBaseUrl(next?.baseUrl || "");
                    setModel(next?.model || "");
                    setApiKey("");
                    invalidate();
                  }}
                >
                  {status ? (
                    Object.entries(status.defaults.surfaces).map(
                      ([id, item]) => (
                        <option key={id} value={id}>
                          {item.label}
                        </option>
                      ),
                    )
                  ) : (
                    <option value="gemrouter">Gemrouter</option>
                  )}
                </select>
              </label>
              <label>
                Model
                <input
                  list="kernaid-models"
                  value={model}
                  onChange={(e) => {
                    setModel(e.target.value);
                    setVerified(false);
                  }}
                />
                <datalist id="kernaid-models">
                  {models.map((id) => (
                    <option key={id} value={id} />
                  ))}
                </datalist>
              </label>
              <details>
                <summary>Endpoint and API key</summary>
                <label>
                  API base URL
                  <input
                    type="url"
                    value={baseUrl}
                    onChange={(e) => {
                      setBaseUrl(e.target.value);
                      setApiKey("");
                      invalidate();
                    }}
                  />
                </label>
                <label>
                  API key
                  <input
                    type="password"
                    autoComplete="off"
                    value={apiKey}
                    placeholder={
                      status?.credentialPresent &&
                      status.config.surface === surface &&
                      status.config.baseUrl === baseUrl
                        ? "Configured · enter a new key to replace"
                        : "Enter your provider key"
                    }
                    onChange={(e) => {
                      setApiKey(e.target.value);
                      setVerified(false);
                    }}
                  />
                </label>
                <p>
                  Keys stay in this live session. Changing the endpoint requires
                  a new key.
                </p>
              </details>
              <button
                onClick={() =>
                  void work("Loading available models…", async () => {
                    await configure();
                    const result = await call<{ models: string[] }>("models");
                    setModels(result.models);
                  })
                }
              >
                Load models
              </button>
              <button
                className="connection-primary"
                disabled={!model}
                onClick={() =>
                  void work("Checking the model connection…", async () => {
                    await configure();
                    const reply = await call<{ answer: string }>("chat", {
                      conversationId: conversationId.current,
                      message:
                        "Reply with a brief welcome to KernAid and ask what is wrong with this computer. Do not search the web for this greeting.",
                    });
                    setMessages([{ role: "KernAid", text: reply.answer }]);
                    setVerified(true);
                  })
                }
              >
                Connect to assistant
              </button>
              <p>
                {verified
                  ? `Connected to ${model} · Pi assistant ready`
                  : "Default: Gemrouter · gemini-3.8-flash"}
              </p>
            </fieldset>
          </div>
          {(verified || messages.length > 0) && (
            <div className="connection-chat" aria-label="Recovery assistant">
              <h2>Tell us what happened</h2>
              <p>
                Pi can search the web with SearXNG. Only your messages and any
                summary you explicitly approve below are sent to the model. File
                contents are not attached.
              </p>
              <div aria-live="polite">
                {messages.map((item, index) => (
                  <div
                    className={`connection-message ${item.role === "You" ? "user" : "assistant"}`}
                    key={index}
                  >
                    <strong>{item.role}</strong>
                    <p>{item.text}</p>
                  </div>
                ))}
              </div>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const text = message.trim();
                  if (!text || !verified || inFlight.current) return;
                  const attachment = shareContext ? context : undefined;
                  const submittedContextKey = contextKey;
                  void work("Pi is answering…", async () => {
                    setMessages((items) => [
                      ...items,
                      {
                        role: "You",
                        text: attachment
                          ? `${text}\n[Approved read-only summary attached · separate analysis]`
                          : text,
                      },
                    ]);
                    setMessage("");
                    setContextConsent(undefined);
                    const result = await call<{ answer: string }>("chat", {
                      message: text,
                      conversationId: conversationId.current,
                      ...(attachment
                        ? {
                            context: attachment,
                            expectedProvider: { surface, baseUrl, model },
                          }
                        : {}),
                    });
                    if (submittedContextKey !== latestContextKey.current)
                      return;
                    setMessages((items) => [
                      ...items,
                      { role: "KernAid", text: result.answer },
                    ]);
                  });
                }}
              >
                {context && (
                  <div className="connection-context">
                    <h3>Let Pi explain this computer’s checks</h3>
                    <p>
                      {context.osFamily === "windows" ? "Windows" : "Linux"} ·
                      read-only inspection ·{" "}
                      {context.installationConfirmed
                        ? "installation detected"
                        : "installation not confirmed"}
                      . This summary contains only boot/update indicators and
                      counts. No names, disk IDs, paths, file contents or keys.
                    </p>
                    <details>
                      <summary>Review the exact data to share</summary>
                      <pre>{preview}</pre>
                    </details>
                    <label className="connection-consent">
                      <input
                        type="checkbox"
                        checked={shareContext}
                        disabled={Boolean(busy)}
                        onChange={(e) =>
                          setContextConsent(
                            e.target.checked ? contextBinding : undefined,
                          )
                        }
                      />
                      Share this summary with {status?.config.label || surface}{" "}
                      ({model}) for this question only.
                    </label>
                    <p>
                      Separate analysis without earlier chat history. Approval
                      resets after sending; replies are advice, not an executed
                      repair.
                    </p>
                  </div>
                )}
                <label>
                  Your question
                  <textarea
                    maxLength={4000}
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="For example: Windows stopped starting after an update."
                  />
                </label>
                <button
                  disabled={Boolean(busy) || !verified || !message.trim()}
                >
                  Send
                </button>
              </form>
            </div>
          )}
          {busy && (
            <p role="status" className="connection-progress">
              {busy}
            </p>
          )}
          {error && (
            <p role="alert" className="connection-error">
              {error}
            </p>
          )}
          <div className="connection-actions">
            <button
              className="connection-primary"
              disabled={!verified || Boolean(busy)}
              onClick={finish}
            >
              Continue to system diagnosis →
            </button>
            <button onClick={finish}>Continue offline</button>
          </div>
        </>
      )}
    </section>
  );
}
