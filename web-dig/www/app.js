import init, { dig, supported_record_types } from "./pkg/web_dig.js";

const ENDPOINTS = {
    "cloudflare-doh": {
        protocol: "doh",
        url: "https://cloudflare-dns.com/dns-query",
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
const customServerRow = document.getElementById("custom-server-row");
const customServerLabel = document.getElementById("custom-server-label");
const customServerInput = document.getElementById("custom-server-input");
const digForm = document.getElementById("dig-form");
const digBtn = document.getElementById("dig-btn");
const btnText = document.getElementById("btn-text");
const outputBox = document.getElementById("output-box");
const statusBadge = document.getElementById("status-badge");
const copyBtn = document.getElementById("copy-btn");

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

function setStatus(text, type) {
    statusBadge.style.display = "inline-block";
    statusBadge.className = `status-badge ${type}`;
    statusBadge.textContent = text;
}

function clearStatus() {
    statusBadge.style.display = "none";
    statusBadge.textContent = "";
}

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
});

document.querySelectorAll(".chip-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
        domainInput.value = btn.dataset.domain;
        typeSelect.value = btn.dataset.type;
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

    const domain = domainInput.value.trim();
    const rtype = typeSelect.value;

    if (!domain) {
        domainInput.focus();
        return;
    }

    let protocol, serverUrl;
    try {
        const endpoint = resolveEndpoint();
        protocol = endpoint.protocol;
        serverUrl = endpoint.url;
    } catch (err) {
        setStatus(err.message, "error");
        outputBox.textContent = `Error: ${err.message}`;
        outputBox.classList.remove("empty");
        return;
    }

    digBtn.disabled = true;
    btnText.textContent = "Digging...";
    setStatus("Querying...", "loading");
    outputBox.classList.remove("empty");
    outputBox.textContent = `;; Querying ${domain} IN ${rtype} via ${serverUrl} (${protocol.toUpperCase()})...`;

    const startTime = performance.now();

    try {
        const result = await dig(domain, rtype, serverUrl, protocol);
        const duration = Math.round(performance.now() - startTime);

        outputBox.textContent = result;
        setStatus(`${duration} ms`, "success");
    } catch (err) {
        const duration = Math.round(performance.now() - startTime);
        const message = typeof err === "string" ? err : err?.message || String(err);

        outputBox.textContent = `;; Connection failed after ${duration} ms\n;; Error: ${message}\n\n;; Note: Browser CORS policy or network restrictions may block some DoH endpoints.`;
        setStatus("Error", "error");
    } finally {
        digBtn.disabled = false;
        btnText.textContent = "Dig";
    }
});

// Initialize WASM
async function run() {
    try {
        await init();

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
