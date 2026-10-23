const $ = (selector) => document.querySelector(selector);
let capture = null;
let activeCampaign = null;
let pollTimer = null;

const fileInput = $("#pcap-file");
const dropzone = $("#dropzone");
fileInput.addEventListener("change", () => fileInput.files[0] && upload(fileInput.files[0]));
["dragenter", "dragover"].forEach((event) => dropzone.addEventListener(event, (e) => { e.preventDefault(); dropzone.classList.add("drag"); }));
["dragleave", "drop"].forEach((event) => dropzone.addEventListener(event, (e) => { e.preventDefault(); dropzone.classList.remove("drag"); }));
dropzone.addEventListener("drop", (event) => event.dataTransfer.files[0] && upload(event.dataTransfer.files[0]));

async function upload(file) {
  log("info", `Đang phân tích ${file.name}…`);
  const body = new FormData(); body.append("file", file);
  try {
    const response = await fetch("/api/pcaps", {method: "POST", body});
    if (!response.ok) throw new Error(await response.text());
    capture = await response.json();
    $("#capture-summary").classList.remove("hidden");
    $("#capture-summary").innerHTML = `<strong>${escapeHtml(capture.filename)}</strong><br>${capture.packet_count} gói tin, ${capture.seed_count} payload seed, giao thức ${escapeHtml(capture.protocols.join(", "))}`;
    $("#run-button").disabled = capture.seed_count === 0;
    $("#run-hint").textContent = capture.seed_count ? "File hợp lệ, bạn có thể chạy chiến dịch." : "File này không có payload nào để làm seed. Hãy chọn PCAP khác.";
    log("info", `PCAP hợp lệ: ${capture.seed_count} seed, ${Object.keys(capture.state_graph).length} trạng thái nguồn.`);
  } catch (error) { log("error", `Upload thất bại: ${error.message}`); }
}

$("select[name=protocol]").addEventListener("change", (event) => {
  $("#network-fields").classList.toggle("hidden", event.target.value === "dry-run");
});

$("#campaign-form").addEventListener("submit", async (event) => {
  event.preventDefault(); if (!capture) return;
  const form = new FormData(event.target);
  const config = {
    name: form.get("name"), seed_path: capture.path, protocol: form.get("protocol"),
    target_host: form.get("target_host") || "127.0.0.1", target_port: Number(form.get("target_port") || 0),
    authorized: form.get("authorized") === "on", max_cases: Number(form.get("max_cases")),
    delay_seconds: Number(form.get("delay_seconds")), random_seed: Number(form.get("random_seed")),
    smart_selection: form.get("smart_selection") === "on", state_aware: form.get("state_aware") === "on"
  };
  const body = new FormData(); body.append("config_json", JSON.stringify(config));
  try {
    const response = await fetch("/api/campaigns", {method: "POST", body});
    if (!response.ok) throw new Error(await response.text());
    const created = await response.json(); activeCampaign = created.id;
    setStatus("running"); log("info", `Chiến dịch ${activeCampaign.slice(0, 8)} đã bắt đầu.`);
    $("#run-button").disabled = true; poll();
  } catch (error) { log("error", `Không thể chạy: ${error.message}`); }
});

async function poll() {
  if (!activeCampaign) return;
  try {
    const response = await fetch(`/api/campaigns/${activeCampaign}`);
    const campaign = await response.json(); updateCampaign(campaign);
    loadSecurity();
    if (["running", "created"].includes(campaign.status)) pollTimer = setTimeout(poll, 700);
    else { $("#run-button").disabled = false; loadHistory(); loadSecurity(); }
  } catch (error) { log("error", `Mất kết nối dashboard: ${error.message}`); }
}

const SECURITY_LABELS = {secure:"An toàn", vulnerable:"Phát hiện lỗ hổng", unreachable:"Mất kết nối", pending:"Đang chờ", "not-monitored":"Không giám sát", monitoring:"Đang giám sát"};
async function loadSecurity() {
  try {
    const data = await (await fetch("/api/security")).json();
    const summary = $("#security-summary");
    if (data.vulnerable > 0) { summary.className = "badge failed"; summary.textContent = `${data.vulnerable} thiết bị nghi lỗ hổng`; }
    else if (data.unreachable > 0) { summary.className = "badge stopped"; summary.textContent = `${data.unreachable} thiết bị mất kết nối`; }
    else { summary.className = "badge completed"; summary.textContent = "Không có cảnh báo"; }
    const box = $("#security-alerts");
    box.innerHTML = data.alerts.length
      ? data.alerts.map((a) => `<p class="error"><time>${a.created_at.slice(11,19)}</time>[security] ${escapeHtml(a.message)}${a.data && a.data.last_payload_hex ? `<br><code>payload: ${escapeHtml(String(a.data.last_payload_hex).slice(0,96))}…</code>` : ""}</p>`).join("")
      : '<p class="muted">Chưa có cảnh báo. Khi thiết bị ngừng phản hồi trong lúc fuzz, cảnh báo sẽ hiện ở đây kèm payload cuối cùng.</p>';
  } catch (_) { /* keep prior view on transient failure */ }
}

function updateCampaign(campaign) {
  const metrics = campaign.metrics || {};
  $("#sent").textContent = metrics.sent_cases || 0;
  $("#speed").textContent = Number(metrics.packets_per_second || 0).toFixed(1);
  $("#crashes").textContent = metrics.crashes || 0;
  $("#crash-card").classList.toggle("alert", (metrics.crashes || 0) > 0);
  $("#memory").textContent = metrics.memory_leak_rate == null ? "—" : Number(metrics.memory_leak_rate).toFixed(3);
  const total = metrics.total_cases || 0, sent = metrics.sent_cases || 0;
  $("#progress-label").textContent = `${sent} / ${total}`;
  const percent = total ? Math.min(100, sent / total * 100) : 0;
  $("#progress-bar").style.width = `${percent}%`;
  $("#progress-track").setAttribute("aria-valuenow", Math.round(percent));
  setStatus(campaign.status);
  $("#event-log").innerHTML = campaign.recent_events.length ? campaign.recent_events.map(eventLine).join("") : '<p class="muted">Chưa có sự kiện.</p>';
  const actions = $("#report-actions"); actions.classList.toggle("hidden", !["completed", "stopped", "failed"].includes(campaign.status));
  $("#csv-link").href = `/api/campaigns/${campaign.id}/report.csv`;
  $("#pdf-link").href = `/api/campaigns/${campaign.id}/report.pdf`;
}

const STATUS_LABELS = {created:"Đang tạo",running:"Đang chạy",completed:"Hoàn tất",stopped:"Đã dừng",failed:"Thất bại"};
function setStatus(status) {
  const badge = $("#status-badge"); badge.className = `badge ${status}`;
  badge.textContent = STATUS_LABELS[status] || "Chưa chạy";
}
function eventLine(item) { return `<p class="${item.level}"><time>${item.created_at.slice(11,19)}</time>[${escapeHtml(item.kind)}] ${escapeHtml(item.message)}</p>`; }
function log(level, message) { const consoleEl = $("#event-log"); if (consoleEl.querySelector(".muted")) consoleEl.innerHTML=""; consoleEl.insertAdjacentHTML("beforeend", `<p class="${level}"><time>${new Date().toLocaleTimeString("vi-VN")}</time>${escapeHtml(message)}</p>`); consoleEl.scrollTop = consoleEl.scrollHeight; }
function escapeHtml(value) { const node=document.createElement("span"); node.textContent=String(value); return node.innerHTML; }
$("#clear-log").addEventListener("click", () => $("#event-log").innerHTML='<p class="muted">Đã xóa nhật ký.</p>');

function setServer(online) {
  const el = $("#server-status"); el.className = `server-status ${online ? "online" : "offline"}`;
  el.lastElementChild.textContent = online ? "Máy chủ đang hoạt động" : "Mất kết nối máy chủ";
}

let historyCache = [];
function renderHistory() {
  const query = ($("#history-filter").value || "").trim().toLowerCase();
  const rows = historyCache.filter((item) =>
    !query || item.name.toLowerCase().includes(query) || item.status.toLowerCase().includes(query)
    || String(item.metrics.security_status || "").toLowerCase().includes(query));
  $("#history").innerHTML = rows.length ? rows.slice(0, 12).map((item) => {
    const sec = item.metrics.security_status || "pending";
    const vuln = sec === "vulnerable";
    return `<article${vuln ? ' class="vulnerable"' : ""}><h3>${escapeHtml(item.name)}</h3>`
      + `<span><span class="badge ${escapeHtml(item.status)}">${STATUS_LABELS[item.status] || escapeHtml(item.status)}</span></span>`
      + `<time>${item.created_at.slice(0,16).replace("T"," ")}</time>`
      + `<p class="stats"><strong>${item.metrics.sent_cases || 0}</strong> test case, <strong>${Number(item.metrics.packets_per_second || 0).toFixed(1)}</strong> gói/giây, <strong>${item.metrics.crashes || 0}</strong> crash</p>`
      + `<span class="sec-tag ${sec}">${SECURITY_LABELS[sec] || sec}</span></article>`;
  }).join("") : (historyCache.length ? '<p class="muted">Không có chiến dịch nào khớp bộ lọc.</p>' : '<p class="muted">Chưa có chiến dịch nào. Nạp PCAP và chạy chiến dịch đầu tiên ở bảng bên trên.</p>');
}
async function loadHistory() {
  try {
    historyCache = await (await fetch("/api/campaigns")).json();
    renderHistory(); setServer(true);
  } catch (_) { setServer(false); /* retain prior history on transient failures */ }
}
$("#history-filter").addEventListener("input", renderHistory);
$("#refresh-history").addEventListener("click", loadHistory);
loadHistory(); loadSecurity();

