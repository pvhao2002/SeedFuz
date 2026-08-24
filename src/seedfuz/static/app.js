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
    $("#capture-summary").innerHTML = `<strong>${escapeHtml(capture.filename)}</strong><br>${capture.packet_count} packets · ${capture.seed_count} payload seeds · ${capture.protocols.join(", ")}`;
    $("#run-button").disabled = capture.seed_count === 0;
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
    if (["running", "created"].includes(campaign.status)) pollTimer = setTimeout(poll, 700);
    else { $("#run-button").disabled = false; loadHistory(); }
  } catch (error) { log("error", `Mất kết nối dashboard: ${error.message}`); }
}

function updateCampaign(campaign) {
  const metrics = campaign.metrics || {};
  $("#sent").textContent = metrics.sent_cases || 0;
  $("#speed").textContent = Number(metrics.packets_per_second || 0).toFixed(1);
  $("#crashes").textContent = metrics.crashes || 0;
  $("#memory").textContent = metrics.memory_leak_rate == null ? "—" : Number(metrics.memory_leak_rate).toFixed(3);
  const total = metrics.total_cases || 0, sent = metrics.sent_cases || 0;
  $("#progress-label").textContent = `${sent} / ${total}`;
  $("#progress-bar").style.width = `${total ? Math.min(100, sent / total * 100) : 0}%`;
  setStatus(campaign.status);
  $("#event-log").innerHTML = campaign.recent_events.length ? campaign.recent_events.map(eventLine).join("") : '<p class="muted">Chưa có sự kiện.</p>';
  const actions = $("#report-actions"); actions.classList.toggle("hidden", !["completed", "stopped", "failed"].includes(campaign.status));
  $("#csv-link").href = `/api/campaigns/${campaign.id}/report.csv`;
  $("#pdf-link").href = `/api/campaigns/${campaign.id}/report.pdf`;
}

function setStatus(status) {
  const badge = $("#status-badge"); badge.className = `badge ${status}`;
  badge.textContent = ({created:"Đang tạo",running:"Đang chạy",completed:"Hoàn tất",stopped:"Đã dừng",failed:"Thất bại"})[status] || "Chưa chạy";
}
function eventLine(item) { return `<p class="${item.level}"><time>${item.created_at.slice(11,19)}</time>[${escapeHtml(item.kind)}] ${escapeHtml(item.message)}</p>`; }
function log(level, message) { const consoleEl = $("#event-log"); if (consoleEl.querySelector(".muted")) consoleEl.innerHTML=""; consoleEl.insertAdjacentHTML("beforeend", `<p class="${level}"><time>${new Date().toLocaleTimeString("vi-VN")}</time>${escapeHtml(message)}</p>`); consoleEl.scrollTop = consoleEl.scrollHeight; }
function escapeHtml(value) { const node=document.createElement("span"); node.textContent=String(value); return node.innerHTML; }
$("#clear-log").addEventListener("click", () => $("#event-log").innerHTML='<p class="muted">Màn hình đã được xóa.</p>');

async function loadHistory() {
  try {
    const campaigns = await (await fetch("/api/campaigns")).json();
    $("#history").innerHTML = campaigns.length ? campaigns.slice(0, 9).map((item) => `<article><h3>${escapeHtml(item.name)}</h3><p><strong>${item.status}</strong> · ${item.created_at.slice(0,19).replace("T"," ")}</p><p>${item.metrics.sent_cases || 0} cases · ${Number(item.metrics.packets_per_second || 0).toFixed(1)} pkt/s · ${item.metrics.crashes || 0} crash</p></article>`).join("") : '<p class="muted">Chưa có chiến dịch.</p>';
  } catch (_) { /* retain prior history on transient failures */ }
}
$("#refresh-history").addEventListener("click", loadHistory); loadHistory();

