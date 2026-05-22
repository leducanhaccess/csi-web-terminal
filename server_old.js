import express from "express";
import http from "http";
import { Server } from "socket.io";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import AdmZip from "adm-zip";

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;
const FIXED_IFACE = "eth6";
const CAPTURE_DIR = path.resolve("captures");
const TMP_DIR = path.resolve("tmp");

fs.mkdirSync(CAPTURE_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

app.use(express.json());
app.use(express.static("public"));
app.use("/captures", express.static(CAPTURE_DIR));

const rxState = {
  rx1: { status: "offline", message: "" },
  rx2: { status: "offline", message: "" },
  rx3: { status: "offline", message: "" }
};

const captureHistory = [];

function emitState(socket = null) {
  const payload = { rxState, captureHistory };
  if (socket) socket.emit("state", payload);
  else io.emit("state", payload);
}

function setRxStatus(name, status, message = "") {
  if (!rxState[name]) return;
  rxState[name] = { status, message };
  emitState();
}

function log(socket, msg) {
  socket.emit("terminal-log", String(msg));
}

function notify(socket, type, message) {
  socket.emit("notify", { type, message });
}

function makeCaptureId() {
  const d = new Date();
  const p = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function sanitizeHost(value, label) {
  const v = String(value || "").trim();
  if (!/^[a-zA-Z0-9._:-]+$/.test(v)) {
    throw new Error(`${label} không hợp lệ`);
  }
  return v;
}

function sanitizeUser(value, label) {
  const v = String(value || "").trim();
  if (!/^[a-zA-Z0-9._-]+$/.test(v)) {
    throw new Error(`${label} không hợp lệ`);
  }
  return v;
}

function sanitizeKeyPath(value) {
  const v = String(value || "").trim();
  if (!v) return "";
  if (!/^[a-zA-Z0-9_./~:-]+$/.test(v)) {
    throw new Error("SSH key path không hợp lệ");
  }
  return v;
}

function intInRange(value, min, max, label) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${label} phải là số nguyên từ ${min} đến ${max}`);
  }
  return n;
}

function intInList(value, list, label) {
  const n = Number(value);
  if (!list.includes(n)) {
    throw new Error(`${label} phải thuộc: ${list.join(", ")}`);
  }
  return n;
}

function getTx(cfg) {
  return {
    ip: sanitizeHost(cfg.ip, "TX IP"),
    hostname: sanitizeHost(cfg.hostname || "tx", "TX hostname"),
    username: sanitizeUser(cfg.username, "TX username"),
    password: String(cfg.password || ""),
    authMode: cfg.authMode === "key" ? "key" : "password",
    keyPath: sanitizeKeyPath(cfg.keyPath || ""),
    channel: intInRange(cfg.channel, 1, 196, "TX channel"),
    bandwidth: intInList(cfg.bandwidth, [20, 40, 80], "TX bandwidth")
  };
}

function getRxGlobal(cfg) {
  return {
    channel: intInRange(cfg.channel, 1, 196, "RX channel"),
    bandwidth: intInList(cfg.bandwidth, [20, 40, 80], "RX bandwidth"),
    core: intInList(cfg.core, [1, 2, 3, 4], "RX core"),
    stream: intInList(cfg.stream, [1, 2, 3, 4], "RX stream"),
    duration: intInRange(cfg.duration || 30, 1, 3600, "Capture duration")
  };
}

function getRxList(list) {
  if (!Array.isArray(list) || list.length !== 3) {
    throw new Error("Phải có đúng 3 RX");
  }

  return list.map((rx, idx) => {
    const name = sanitizeHost(rx.hostname || `rx${idx + 1}`, `RX${idx + 1} hostname`);
    if (!/^rx[123]$/.test(name)) {
      throw new Error("Hostname RX phải là rx1, rx2, rx3");
    }

    return {
      name,
      ip: sanitizeHost(rx.ip, `${name} IP`),
      username: sanitizeUser(rx.username, `${name} username`),
      password: String(rx.password || ""),
      authMode: rx.authMode === "key" ? "key" : "password",
      keyPath: sanitizeKeyPath(rx.keyPath || "")
    };
  });
}

function runProcess(socket, command, args, options = {}) {
  return new Promise((resolve, reject) => {
    log(socket, `\n$ ${command} ${args.join(" ")}\n`);

    const child = spawn(command, args, {
      shell: false,
      env: { ...process.env, ...(options.env || {}) },
      cwd: options.cwd || process.cwd()
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", data => {
      stdout += data.toString();
      log(socket, data.toString());
    });

    child.stderr.on("data", data => {
      stderr += data.toString();
      log(socket, data.toString());
    });

    child.on("error", err => {
      log(socket, `\n[PROCESS ERROR] ${err.message}\n`);
      reject(err);
    });

    child.on("close", code => {
      log(socket, `\n[EXIT CODE] ${code}\n`);
      if (code === 0) resolve({ code, stdout, stderr });
      else reject(new Error(stderr || stdout || `${command} exited with code ${code}`));
    });
  });
}

function buildSshCommand(auth) {
  if (auth.authMode === "key") {
    if (!auth.keyPath) throw new Error("SSH key mode cần keyPath");
    return {
      command: "ssh",
      argsBase: [
        "-i", auth.keyPath,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null"
      ],
      env: {}
    };
  }

  return {
    command: "sshpass",
    argsBase: [
      "-e",
      "ssh",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null"
    ],
    env: { SSHPASS: auth.password }
  };
}

function txRemoteCmd(action, tx) {
  if (action === "configure") {
    return [
      `/usr/sbin/wl -i ${FIXED_IFACE} country US`,
      `/usr/sbin/wl -i ${FIXED_IFACE} chanspec ${tx.channel}/${tx.bandwidth}`,
      `/usr/sbin/wl -i ${FIXED_IFACE} up`,
      `echo TX_WIFI_CONFIGURED_${FIXED_IFACE}_${tx.channel}_${tx.bandwidth}`
    ].join(" && ");
  }

  if (!["init", "start", "stop", "deinit"].includes(action)) {
    throw new Error("TX action không hợp lệ");
  }

  return `/jffs/tx_task.sh ${FIXED_IFACE} ${action}`;
}

async function runTx(socket, action, cfg) {
  const tx = getTx(cfg);
  const ssh = buildSshCommand(tx);
  const remoteCmd = txRemoteCmd(action, tx);
  const args = [...ssh.argsBase, `${tx.username}@${tx.ip}`, remoteCmd];
  return runProcess(socket, ssh.command, args, { env: ssh.env });
}

function writeTempInventory(rxList) {
  const file = path.join(TMP_DIR, `inventory_${Date.now()}_${Math.random().toString(16).slice(2)}.ini`);
  const lines = ["[rx]"];

  for (const rx of rxList) {
    const vars = [
      `ansible_host=${rx.ip}`,
      `ansible_user=${rx.username}`,
      `ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'`
    ];

    if (rx.authMode === "key") {
      if (!rx.keyPath) throw new Error(`${rx.name}: SSH key mode cần keyPath`);
      vars.push(`ansible_ssh_private_key_file=${rx.keyPath}`);
    } else {
      const safePass = rx.password.replace(/'/g, "'\"'\"'");
      vars.push(`ansible_password='${safePass}'`);
    }

    lines.push(`${rx.name} ${vars.join(" ")}`);
  }

  fs.writeFileSync(file, lines.join("\n") + "\n", { encoding: "utf-8", mode: 0o600 });
  return file;
}

async function runAnsible(socket, playbook, rxList, extraVars) {
  const inventory = writeTempInventory(rxList);

  const args = [
    "-i", inventory,
    playbook,
    "-e", `iface=${FIXED_IFACE}`
  ];

  for (const [k, v] of Object.entries(extraVars || {})) {
    args.push("-e", `${k}=${v}`);
  }

  try {
    return await runProcess(socket, "ansible-playbook", args, {
      env: { ANSIBLE_HOST_KEY_CHECKING: "False" }
    });
  } finally {
    try {
      fs.unlinkSync(inventory);
    } catch {}
  }
}

function addHistory(record) {
  captureHistory.unshift(record);
  while (captureHistory.length > 20) captureHistory.pop();
  emitState();
}

function zipCapture(socket, id) {
  const files = ["rx1", "rx2", "rx3"].map(rx => path.join(CAPTURE_DIR, `${rx}_${id}.pcap`));
  const missing = files.filter(f => !fs.existsSync(f));

  if (missing.length) {
    throw new Error(`Thiếu file PCAP: ${missing.map(f => path.basename(f)).join(", ")}`);
  }

  const zipPath = path.join(CAPTURE_DIR, `csi_capture_${id}.zip`);
  const zip = new AdmZip();

  for (const file of files) {
    zip.addLocalFile(file);
  }

  zip.writeZip(zipPath);
  log(socket, `\n[ZIP] Created ${zipPath}\n`);
  return `/captures/${path.basename(zipPath)}`;
}

io.on("connection", socket => {
  log(socket, `Connected. Fixed interface = ${FIXED_IFACE}\n`);
  emitState(socket);

  socket.on("tx-test", async cfg => {
    try {
      const tx = getTx(cfg);
      const ssh = buildSshCommand(tx);
      await runProcess(socket, ssh.command, [
        ...ssh.argsBase,
        `${tx.username}@${tx.ip}`,
        `echo TX_SSH_OK && hostname || true`
      ], { env: ssh.env });

      notify(socket, "success", "Test SSH TX thành công");
    } catch (err) {
      notify(socket, "error", `Test SSH TX lỗi: ${err.message}`);
    }
  });

  socket.on("rx-test", async cfg => {
    let rxList;
    try {
      rxList = getRxList(cfg.rxList);
      rxList.forEach(rx => setRxStatus(rx.name, "offline", "Testing SSH..."));

      await runAnsible(socket, "ansible/rx_test.yml", rxList, {});

      rxList.forEach(rx => setRxStatus(rx.name, "online", "SSH OK"));
      notify(socket, "success", "Test SSH 3 RX thành công");
    } catch (err) {
      if (rxList) rxList.forEach(rx => setRxStatus(rx.name, "error", "SSH test failed"));
      notify(socket, "error", `Test SSH RX lỗi: ${err.message}`);
    }
  });

  socket.on("tx-configure", async cfg => {
    try {
      await runTx(socket, "configure", cfg);
      notify(socket, "success", `TX configured: ${FIXED_IFACE} ${cfg.channel}/${cfg.bandwidth}`);
    } catch (err) {
      notify(socket, "error", `Configure TX lỗi: ${err.message}`);
    }
  });

  socket.on("tx-action", async cfg => {
    try {
      await runTx(socket, cfg.action, cfg);
      notify(socket, "success", `TX ${cfg.action} thành công`);
    } catch (err) {
      notify(socket, "error", `TX action lỗi: ${err.message}`);
    }
  });

  socket.on("rx-configure", async cfg => {
    let rxList;
    try {
      rxList = getRxList(cfg.rxList);
      const rx = getRxGlobal(cfg);

      rxList.forEach(r => setRxStatus(r.name, "online", "Configuring..."));

      await runAnsible(socket, "ansible/rx_configure.yml", rxList, {
        channel: rx.channel,
        bandwidth: rx.bandwidth,
        core: rx.core,
        stream: rx.stream
      });

      rxList.forEach(r => setRxStatus(r.name, "configured", `${FIXED_IFACE} ${rx.channel}/${rx.bandwidth} C${rx.core} S${rx.stream}`));
      notify(socket, "success", `3 RX configured: ${FIXED_IFACE} ${rx.channel}/${rx.bandwidth}, core=${rx.core}, stream=${rx.stream}`);
    } catch (err) {
      if (rxList) rxList.forEach(r => setRxStatus(r.name, "error", "Configure failed"));
      notify(socket, "error", `Configure RX lỗi: ${err.message}`);
    }
  });

  socket.on("rx-capture", async cfg => {
    let rxList;
    try {
      rxList = getRxList(cfg.rxList);
      const duration = intInRange(cfg.duration, 1, 3600, "Capture duration");
      const id = makeCaptureId();

      rxList.forEach(r => setRxStatus(r.name, "capturing", `Capturing ${duration}s, ID=${id}`));

      await runAnsible(socket, "ansible/rx_capture.yml", rxList, {
        duration,
        capture_id: id
      });

      socket.emit("capture-id", id);

      addHistory({
        id,
        timestamp: new Date().toISOString(),
        duration,
        status: "capturing",
        zip: ""
      });

      notify(socket, "success", `Đã bắt đầu capture ${duration}s. Capture ID: ${id}`);
    } catch (err) {
      if (rxList) rxList.forEach(r => setRxStatus(r.name, "error", "Capture start failed"));
      notify(socket, "error", `Start capture lỗi: ${err.message}`);
    }
  });

  socket.on("rx-fetch", async cfg => {
    let rxList;
    try {
      rxList = getRxList(cfg.rxList);
      const id = sanitizeHost(cfg.captureId, "Capture ID");

      await runAnsible(socket, "ansible/rx_fetch.yml", rxList, {
        capture_id: id
      });

      const zipUrl = zipCapture(socket, id);
      rxList.forEach(r => setRxStatus(r.name, "configured", "PCAP fetched"));

      addHistory({
        id,
        timestamp: new Date().toISOString(),
        duration: cfg.duration || "",
        status: "fetched",
        zip: zipUrl
      });

      socket.emit("pcap-ready", {
        captureId: id,
        zipUrl,
        pcapLinks: ["rx1", "rx2", "rx3"].map(rx => `/captures/${rx}_${id}.pcap`)
      });

      notify(socket, "success", `Đã fetch và zip PCAP: ${id}`);
    } catch (err) {
      if (rxList) rxList.forEach(r => setRxStatus(r.name, "error", "Fetch failed"));
      notify(socket, "error", `Fetch PCAP lỗi: ${err.message}`);
    }
  });
});

server.listen(PORT, () => {
  console.log(`CSI Web Terminal running at http://localhost:${PORT}`);
});
