import init, { dig_dnssec_with_edns, supported_record_types, build_commit, build_time } from "./pkg/web_dig.js";

const ENDPOINTS = {
    "cloudflare-doh": {
        protocol: "doh",
        url: "https://cloudflare-dns.com/dns-query",
    },
    "google-doh": {
        protocol: "doh-get",
        url: "https://dns.google/dns-query",
    },
    "quad9-doh": {
        protocol: "doh-get",
        url: "https://dns9.quad9.net/dns-query",
    },
    "cloudflare-json": {
        protocol: "json",
        url: "https://cloudflare-dns.com/dns-query",
    },
    "google-json": {
        protocol: "json",
        url: "https://dns.google/resolve",
    },
};

const domainInput = document.getElementById("domain-input");
const typeSelect = document.getElementById("type-select");
const endpointSelect = document.getElementById("endpoint-select");
const dnssecModeSelect = document.getElementById("dnssec-mode");
const ednsEnabledInput = document.getElementById("edns-enabled");
const ednsContent = document.getElementById("edns-content");
const payloadSizeInput = document.getElementById("edns-payload-size");
const clientSubnetInput = document.getElementById("client-subnet");
const cookieEnabledInput = document.getElementById("cookie-enabled");
const nsidEnabledInput = document.getElementById("nsid-enabled");
const paddingLengthInput = document.getElementById("padding-length");
const ednsCapabilityNote = document.getElementById("edns-capability-note");
const customServerRow = document.getElementById("custom-server-row");
const customServerLabel = document.getElementById("custom-server-label");
const customServerInput = document.getElementById("custom-server-input");
const digForm = document.getElementById("dig-form");
const outputBox = document.getElementById("output-box");
const statusBadge = document.getElementById("status-badge");
const dnssecIssueBadge = document.getElementById("dnssec-issue-badge");
const copyBtn = document.getElementById("copy-btn");
const traceCard = document.getElementById("trace-card");
const traceCount = document.getElementById("trace-count");
const traceList = document.getElementById("trace-list");
const traceToggleBtn = document.getElementById("trace-toggle-btn");
let queryInProgress = false;

function resolveEndpoint() {
    const choice = endpointSelect.value;
    if (choice.startsWith("custom-")) {
        const protocol = choice === "custom-json" ? "json" : "doh";
        const url = customServerInput.value.trim();
        if (!url) {
            throw new Error("Please specify a custom endpoint URL.");
        }
        return { protocol, url };
    }
    const preset = ENDPOINTS[choice] || ENDPOINTS["cloudflare-doh"];
    return { protocol: preset.protocol, url: preset.url };
}

function selectedProtocolIsJson() {
    return endpointSelect.value.endsWith("json");
}

function updateEdnsControls() {
    const json = selectedProtocolIsJson();
    const localValidation = dnssecModeSelect.value === "local";
    if (localValidation) {
        ednsEnabledInput.checked = true;
    }

    const ednsOff = !ednsEnabledInput.checked;
    ednsEnabledInput.disabled = localValidation;
    ednsContent.hidden = ednsOff;
    payloadSizeInput.disabled = ednsOff || json;
    clientSubnetInput.disabled = ednsOff;
    cookieEnabledInput.disabled = ednsOff || (json && !cookieEnabledInput.checked);
    nsidEnabledInput.disabled = ednsOff || (json && !nsidEnabledInput.checked);
    paddingLengthInput.disabled = ednsOff || (json && Number(paddingLengthInput.value) === 0);

    const notes = [];
    if (json) {
        notes.push("JSON DoH exposes DO and ECS only; provider support varies. COOKIE, NSID, padding, and UDP payload size require binary DoH.");
    }
    if (ednsOff) {
        notes.push("EDNS is disabled; its options will not be sent.");
    }
    if (localValidation) {
        notes.push("Local DNSSEC validation automatically enables EDNS and DO.");
    }
    ednsCapabilityNote.textContent = notes.join(" ");
}

function makeClientCookieHex() {
    if (!globalThis.crypto?.getRandomValues) {
        throw new Error("This browser cannot securely generate a DNS COOKIE.");
    }
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(8));
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function readEdnsOptions(protocol) {
    const ednsEnabled = ednsEnabledInput.checked;
    const clientSubnet = clientSubnetInput.value.trim();
    const paddingLength = Number(paddingLengthInput.value);
    const payloadSize = Number(payloadSizeInput.value);

    if (!Number.isInteger(paddingLength) || paddingLength < 0 || paddingLength > 65535) {
        throw new Error("EDNS padding must be between 0 and 65535 bytes.");
    }
    if (!Number.isInteger(payloadSize) || payloadSize < 512 || payloadSize > 65535) {
        throw new Error("EDNS UDP payload size must be between 512 and 65535 bytes.");
    }
    if (!ednsEnabled && (clientSubnet || cookieEnabledInput.checked || nsidEnabledInput.checked || paddingLength > 0)) {
        throw new Error("Enable EDNS before setting EDNS options.");
    }
    if (protocol === "json" && (cookieEnabledInput.checked || nsidEnabledInput.checked || paddingLength > 0)) {
        throw new Error("This JSON DoH endpoint cannot send COOKIE, NSID, or padding. Switch to binary DoH or turn those options off.");
    }

    return {
        ednsEnabled,
        payloadSize,
        clientSubnet,
        clientCookieHex: cookieEnabledInput.checked ? makeClientCookieHex() : "",
        requestNsid: nsidEnabledInput.checked,
        paddingLength,
    };
}

function setStatus(text, type) {
    statusBadge.style.display = "inline-block";
    statusBadge.className = `status-badge ${type}`;
    statusBadge.textContent = text;
}

function clearStatus() {
    statusBadge.style.display = "none";
    statusBadge.textContent = "";
}

function span(className, text) {
    const el = document.createElement("span");
    el.className = className;
    el.textContent = text;
    return el;
}

function clearTrace() {
    traceCard.hidden = true;
    traceList.replaceChildren();
}

// Renders the local-validation trace. All DNS-derived text is set via
// textContent so response data cannot inject markup.
function renderTrace(entries) {
    clearTrace();
    if (entries.length === 0) return;

    for (const [index, entry] of entries.entries()) {
        const item = document.createElement("li");
        item.className = entry.failed ? "trace-entry failed" : "trace-entry";

        const details = document.createElement("details");
        const summary = document.createElement("summary");
        summary.append(
            span("trace-index", String(index + 1)),
            span("trace-question", entry.question),
            span("trace-flags", entry.flags),
            span("trace-summary", entry.summary),
            span(
                "trace-time",
                `+${Math.round(entry.start_ms)} ms · ${Math.round(entry.elapsed_ms)} ms`,
            ),
        );
        const detail = document.createElement("pre");
        detail.className = "output-box trace-detail";
        detail.textContent = entry.detail;
        details.append(summary, detail);
        item.append(details);
        traceList.append(item);
    }

    traceCount.textContent = `${entries.length} ${entries.length === 1 ? "query" : "queries"}`;
    traceToggleBtn.textContent = "Expand all";
    traceCard.hidden = false;
}

traceToggleBtn.addEventListener("click", () => {
    const all = [...traceList.querySelectorAll("details")];
    const expand = all.some((d) => !d.open);
    all.forEach((d) => {
        d.open = expand;
    });
    traceToggleBtn.textContent = expand ? "Collapse all" : "Expand all";
});

endpointSelect.addEventListener("change", () => {
    const choice = endpointSelect.value;
    if (choice.startsWith("custom-")) {
        customServerRow.classList.add("visible");
        if (choice === "custom-json") {
            customServerLabel.textContent = "Custom JSON API Endpoint URL";
            customServerInput.placeholder = "https://dns.google/resolve";
        } else {
            customServerLabel.textContent = "Custom DoH (RFC 8484) Endpoint URL";
            customServerInput.placeholder = "https://cloudflare-dns.com/dns-query";
        }
        customServerInput.focus();
    } else {
        customServerRow.classList.remove("visible");
    }
    updateEdnsControls();
});

ednsEnabledInput.addEventListener("change", () => {
    if (!ednsEnabledInput.checked) {
        clientSubnetInput.value = "";
        cookieEnabledInput.checked = false;
        nsidEnabledInput.checked = false;
        paddingLengthInput.value = "0";
    }
    updateEdnsControls();
});
dnssecModeSelect.addEventListener("change", updateEdnsControls);
updateEdnsControls();

document.querySelectorAll(".chip-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        domainInput.value = btn.dataset.domain;
        typeSelect.value = btn.dataset.type;
        if (btn.dataset.dnssecMode) {
            dnssecModeSelect.value = btn.dataset.dnssecMode;
            dnssecModeSelect.dispatchEvent(new Event("change", { bubbles: true }));
        }
        digForm.requestSubmit();
    });
});

copyBtn.addEventListener("click", async () => {
    const text = outputBox.textContent;
    if (!text || outputBox.classList.contains("empty")) return;

    try {
        await navigator.clipboard.writeText(text);
        const originalText = copyBtn.textContent;
        copyBtn.textContent = "Copied!";
        setTimeout(() => {
            copyBtn.textContent = originalText;
        }, 1500);
    } catch (err) {
        console.error("Clipboard copy failed", err);
    }
});

digForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (queryInProgress) return;

    const domain = domainInput.value.trim();
    const rtype = typeSelect.value;
    const dnssecMode = dnssecModeSelect.value;

    if (!domain) {
        domainInput.focus();
        return;
    }

    let protocol, serverUrl, ednsOptions;
    try {
        const endpoint = resolveEndpoint();
        protocol = endpoint.protocol;
        serverUrl = endpoint.url;
        ednsOptions = readEdnsOptions(protocol);
    } catch (err) {
        setStatus(err.message, "error");
        outputBox.textContent = `Error: ${err.message}`;
        outputBox.classList.remove("empty");
        return;
    }

    queryInProgress = true;
    digForm.setAttribute("aria-busy", "true");
    const startTime = performance.now();

    try {
        const result = await dig_dnssec_with_edns(
            domain,
            rtype,
            serverUrl,
            protocol,
            dnssecMode,
            ednsOptions.ednsEnabled,
            ednsOptions.payloadSize,
            ednsOptions.clientSubnet,
            ednsOptions.clientCookieHex,
            ednsOptions.requestNsid,
            ednsOptions.paddingLength,
        );
        const duration = Math.round(performance.now() - startTime);
        const output = result.output;
        const trace = result.trace;
        const validationIssue = result.dnssec_error !== undefined;
        result.free();

        outputBox.classList.remove("empty");
        outputBox.textContent = output;
        setStatus(`${duration} ms`, "timing");
        dnssecIssueBadge.hidden = !validationIssue;
        renderTrace(trace);
        trace.forEach((entry) => entry.free());
    } catch (err) {
        const duration = Math.round(performance.now() - startTime);
        const message = typeof err === "string" ? err : err?.message || String(err);

        clearTrace();
        dnssecIssueBadge.hidden = true;
        outputBox.classList.remove("empty");
        outputBox.textContent = `;; Connection failed after ${duration} ms\n;; Error: ${message}\n\n;; Note: Browser CORS policy or network restrictions may block some DoH endpoints.`;
        setStatus("Error", "error");
    } finally {
        queryInProgress = false;
        digForm.removeAttribute("aria-busy");
    }
});

function renderBuildInfo() {
    const el = document.getElementById("build-info");
    if (!el) return;
    const commit = build_commit();
    const time = build_time();
    el.innerHTML = `Commit <a href="https://github.com/bramp/rustdns/commit/${commit}" target="_blank" rel="noopener"><code>${commit}</code></a> · <time>${time}</time>`;
}

// Initialize WASM
async function run() {
    try {
        await init();

        renderBuildInfo();

        // Populate record types from WASM
        const types = supported_record_types();
        if (types && types.length > 0) {
            typeSelect.innerHTML = "";
            for (const t of types) {
                const opt = document.createElement("option");
                opt.value = t;
                opt.textContent = t;
                if (t === "A") opt.selected = true;
                typeSelect.appendChild(opt);
            }
        }

        console.log("rustdns WebAssembly module loaded successfully.");
    } catch (err) {
        console.error("Failed to initialize WASM module", err);
        outputBox.textContent = `Failed to load WebAssembly module: ${err}`;
        setStatus("WASM Error", "error");
    }
}

run();
