import {decode, makePeer, makeChannel, transcript} from "./protocol.mjs";
import {runProbe} from "./ceremony.mjs";
import {describeFailure} from "./failure.mjs";
import {requestGesture} from "./gesture.mjs";
import {watchDeadline} from "./deadline.mjs";

const status = document.querySelector("#status");
const button = document.querySelector("#continue");
const code = document.querySelector("#code");
const cancel = document.querySelector("#cancel");
const abort = new AbortController();
let channel, notifyAbort, stopping;
let stage = "initialization";
let userCancelled = false;
let stopDeadline = () => {};
function finishAbort() {
  return stopping ??= (async () => {
    try { if (notifyAbort && channel) await notifyAbort(); } catch (_) {}
    channel?.close();
  })();
}
cancel.onclick = async () => {
  userCancelled = true;
  abort.abort();
  await finishAbort();
  button.disabled = true; cancel.disabled = true;
  status.textContent = "Cancelled. The paired CLI has been notified; unreachable sessions expire automatically.";
};
window.addEventListener("pagehide", () => { abort.abort(); channel?.close(); });
function gesture(label, action) {
  status.textContent = label === "Create test passkey"
    ? "Create a development passkey. It remains in your provider until you remove it."
    : label + " — ready.";
  return requestGesture(button, label, abort.signal, () => {
    stage = label;
    status.textContent = label + " — waiting for the browser or CLI.";
    return action();
  });
}

async function main() {
  if (window.top !== window || !window.isSecureContext || !navigator.credentials) throw new Error("Unsupported context");
  const args = new URLSearchParams(location.hash.slice(1));
  history.replaceState(null, "", location.pathname);
  if ([...args.keys()].sort().join(",") !== "endpoint,key,rp,session") throw new Error("Invalid launch");
  const endpoint = new URL(args.get("endpoint"));
  const session = args.get("session");
  decode(session, 24);
  const domain = args.get("rp");
  if (!domain || !(location.hostname === domain || location.hostname.endsWith("." + domain)) ||
      endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1" ||
      !endpoint.port || endpoint.pathname !== "/" + session ||
      endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error("Invalid launch");
  document.querySelector("#domain").textContent = domain;
  const remote = decode(args.get("key"), 32);
  async function post(path, bytes, cancelling = false) {
    const response = await fetch(endpoint + "/" + path, {
      method: "POST", body: bytes, headers: {"Content-Type": "application/octet-stream"},
      credentials: "omit", cache: "no-store", redirect: "error",
      signal: cancelling ? AbortSignal.timeout(2000) : abort.signal, targetAddressSpace: "loopback",
    });
    if (!response.ok) throw new Error("Bridge rejected request");
    const data = new Uint8Array(await response.arrayBuffer());
    if (data.length > 16404) throw new Error("Oversized frame");
    return data;
  }
  notifyAbort = async () => post("abort", await channel.seal(new Uint8Array([0])), true);
  await gesture("Connect to CLI", async () => {
    let peer = await makePeer();
    channel = await makeChannel(peer, remote, transcript(location.origin, domain, session, remote, peer.publicKey));
    await post("hello", peer.publicKey);
    peer = undefined;
    code.textContent = channel.code;
    status.textContent = "Compare every group below with the CLI. Approve in both places only if they match.";
  });
  const request = await gesture("The codes match", async () => {
    const frame = await post("confirm", await channel.seal(new Uint8Array([1])));
    const clear = await channel.open(frame);
    try { return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(clear)); }
    finally { clear.fill(0); }
  });
  if (request.domain !== domain) throw new Error("Wrong RP domain");
  stopDeadline = watchDeadline(request.expiresAt, abort);
  abort.signal.throwIfAborted();
  status.textContent = request.binding
    ? "Use the saved test passkey twice. Both PRF outputs must match."
    : "Create a development passkey, then verify it twice. It will remain in your provider until you remove it.";
  const result = await runProbe(request, location.origin, navigator.credentials, gesture, abort.signal);
  try {
    await post("result", await channel.seal(result));
    status.textContent = "Repeatable PRF received and sent to the paired CLI. This is a development probe, not vault access.";
  } finally { result.fill(0); channel.close(); }
  stopDeadline();
  button.disabled = true; cancel.disabled = true;
}
main().catch(async error => {
  stopDeadline();
  const failure = describeFailure(userCancelled ? new Error("Cancelled") : abort.signal.reason ?? error);
  abort.abort(); await finishAbort();
  button.disabled = true; cancel.disabled = true;
  status.textContent = failure.message + " Stage: " + stage + " (" + failure.code + "). No vault was opened.";
  code.textContent = "";
});
