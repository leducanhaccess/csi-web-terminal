import express from "express";
import http from "http";
import { Server } from "socket.io";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import AdmZip from "adm-zip";

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;
const IFACE = "eth6";
const CAPTURE_DIR = path.join(os.homedir(), "Desktop", "csi_captures");
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

function log(socket, msg) {
  socket.emit("terminal-log", String(msg));
}

function notify(socket, type, message) {
  socket.emit("notify", { type, message });
}

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

function resetInactiveRxStatus(activeRxList) {
  const activeNames = new Set(activeRxList.map(rx => rx.name));

  for (const name of ["rx1", "rx2", "rx3"]) {
    if (!activeNames.has(name)) {
      setRxStatus(name, "offline", "Not used");
    }
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function makeCaptureId() {
  const d = new Date();
  const p = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function safeHost(v, label) {
  v = String(v || "").trim();
  if (!/^[a-zA-Z0-9._:-]+$/.test(v)) {
    throw new Error(`${label} không hợp lệ`);
  }
  return v;
}

function safeUser(v, label) {
  v = String(v || "").trim();
  if (!/^[a-zA-Z0-9._-]+$/.test(v)) {
    throw new Error(`${label} không hợp lệ`);
  }
  return v;
}

function intRange(v, min, max, label) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${label} phải từ ${min} đến ${max}`);
  }
  return n;
}

function intList(v, list, label) {
  const n = Number(v);
  if (!list.includes(n)) {
    throw new Error(`${label} phải thuộc ${list.join(", ")}`);
  }
  return n;
}

function txBandwidthCode(bw) {
  if (Number(bw) === 20) return 1;
  if (Number(bw) === 40) return 2;
  if (Number(bw) === 80) return 3;
  throw new Error("TX bandwidth không hợp lệ");
}

function validateMacFilter(v) {
  v = String(v || "").trim();
  if (!v) return "";

  const mac = "[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}";
  const re = new RegExp(`^${mac}(,${mac})*$`);

  if (!re.test(v)) {
    throw new Error("MAC filter phải có dạng aa:bb:cc:dd:ee:ff hoặc danh sách cách nhau bằng dấu phẩy");
  }

  return v;
}

function validateByteFilter(v) {
  v = String(v || "").trim();
  if (!v) return "";

  if (!/^0x[0-9a-fA-F]{2}$/.test(v)) {
    throw new Error("Byte filter phải có dạng 0x08 hoặc 0x88");
  }

  return v;
}

function getTx(cfg) {
  return {
    ip: safeHost(cfg.ip, "TX IP"),
    hostname: safeHost(cfg.hostname || "tx", "TX hostname"),
    username: safeUser(cfg.username, "TX username"),
    password: String(cfg.password || ""),
    channel: intRange(cfg.channel, 1, 196, "TX channel"),
    bandwidth: intList(cfg.bandwidth, [20, 40, 80], "TX bandwidth")
  };
}

function getRxGlobal(cfg) {
  return {
    channel: intRange(cfg.channel, 1, 196, "RX channel"),
    bandwidth: intList(cfg.bandwidth, [20, 40, 80], "RX bandwidth"),
    core: intList(cfg.core, [1, 2, 3, 4], "RX core"),
    stream: intList(cfg.stream, [1, 2, 3, 4], "RX stream"),
    duration: intRange(cfg.duration || 10, 1, 3600, "Duration"),
    macFilter: validateMacFilter(cfg.macFilter),
    byteFilter: validateByteFilter(cfg.byteFilter)
  };
}

function getRxList(list) {
  if (!Array.isArray(list)) {
    throw new Error("Danh sách RX không hợp lệ");
  }

  const activeList = list.filter(rx => String(rx.ip || "").trim() !== "");

  if (activeList.length < 1) {
    throw new Error("Cần ít nhất 1 RX có IP");
  }

  if (activeList.length > 3) {
    throw new Error("Tối đa 3 RX");
  }

  const out = activeList.map((rx, index) => {
    const name = safeHost(rx.hostname || `rx${index + 1}`, `RX${index + 1} hostname`);

    if (!/^rx[123]$/.test(name)) {
      throw new Error("Hostname RX phải là rx1, rx2 hoặc rx3");
    }

    return {
      name,
      ip: safeHost(rx.ip, `${name} IP`),
      username: safeUser(rx.username, `${name} username`),
      password: String(rx.password || "")
    };
  });

  const ips = out.map(rx => rx.ip);
  if (new Set(ips).size !== ips.length) {
    throw new Error("IP RX bị trùng nhau");
  }

  const names = out.map(rx => rx.name);
  if (new Set(names).size !== names.length) {
    throw new Error("Tên RX bị trùng nhau");
  }

  return out;
}

function checkTxRxIpConflict(tx, rxList) {
  const conflict = rxList.find(rx => rx.ip === tx.ip);
  if (conflict) {
    throw new Error(`TX IP bị trùng với ${conflict.name}: ${tx.ip}`);
  }
}

function runProcess(socket, command, args, options = {}) {
  return new Promise((resolve, reject) => {
    log(socket, `\n$ ${command} ${args.join(" ")}\n`);

    const child = spawn(command, args, {
      shell: false,
      cwd: options.cwd || process.cwd(),
      env: { ...process.env, ...(options.env || {}) }
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

      if (code === 0) {
        resolve({ stdout, stderr, code });
      } else {
        reject(new Error(stderr || stdout || `${command} exited with code ${code}`));
      }
    });
  });
}

function sshArgs(tx, remoteCmd) {
  return [
    "-e",
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    `${tx.username}@${tx.ip}`,
    remoteCmd
  ];
}

async function runTx(socket, action, cfg) {
  const tx = getTx(cfg);

  let cmd = "";

  if (action === "test") {
    cmd = "echo TX_SSH_OK && hostname || true";
  } else if (action === "check") {
    cmd = [
      "test -f /jffs/dhd.ko",
      "test -x /jffs/nexutil",
      "test -x /jffs/tx_task.sh",
      "echo TX_TOOLS_OK"
    ].join(" && ");
  } else if (action === "loadfw") {
    cmd = [
      "/sbin/rmmod dhd 2>/dev/null || true",
      "/sbin/insmod /jffs/dhd.ko",
      "sleep 2",
      `/usr/sbin/wl -i ${IFACE} up || true`,
      "echo TX_FIRMWARE_LOADED"
    ].join(" && ");
  } else if (action === "configure") {
    const bwCode = txBandwidthCode(tx.bandwidth);

    cmd = [
      `/usr/sbin/wl -i ${IFACE} country US`,
      `/usr/sbin/wl -i ${IFACE} chanspec ${tx.channel}/${tx.bandwidth}`,
      `/usr/sbin/wl -i ${IFACE} up`,
      `sed -i 's/^bandwidth=.*/bandwidth=${bwCode}/' /jffs/tx_task.sh`,
      `sed -i 's/^mcs=.*/mcs=0/' /jffs/tx_task.sh`,
      `sed -i 's/^spatial_streams=.*/spatial_streams=1/' /jffs/tx_task.sh`,
      "echo TX_WIFI_AND_TX_TASK_CONFIGURED"
    ].join(" && ");
  } else if (["init", "start", "stop", "deinit"].includes(action)) {
    cmd = `/jffs/tx_task.sh ${IFACE} ${action}`;
  } else {
    throw new Error("TX action không hợp lệ");
  }

  return runProcess(socket, "sshpass", sshArgs(tx, cmd), {
    env: { SSHPASS: tx.password }
  });
}

function writeInventory(rxList) {
  const file = path.join(TMP_DIR, `inventory_${Date.now()}_${Math.random().toString(16).slice(2)}.ini`);
  const lines = ["[rx]"];

  for (const rx of rxList) {
    const pass = rx.password.replace(/'/g, "'\"'\"'");

    lines.push(
      `${rx.name} ansible_host=${rx.ip} ansible_user=${rx.username} ansible_password='${pass}' ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'`
    );
  }

  fs.writeFileSync(file, lines.join("\n") + "\n", { mode: 0o600 });
  return file;
}

async function runAnsible(socket, playbook, rxList, extraVars = {}) {
  const inventory = writeInventory(rxList);

  const args = [
    "-i", inventory,
    playbook,
    "-e", `iface=${IFACE}`
  ];

  for (const [k, v] of Object.entries(extraVars)) {
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

async function makeCsiParam(socket, rx) {
  const args = [
    "-c", `${rx.channel}/${rx.bandwidth}`,
    "-C", String(rx.core),
    "-N", String(rx.stream)
  ];

  if (rx.macFilter) {
    args.push("-m", rx.macFilter);
  }

  if (rx.byteFilter) {
    args.push("-b", rx.byteFilter);
  }

  const result = await runProcess(socket, "mcp", args);
  const param = result.stdout.trim().split(/\s+/).pop();

  if (!param || param.length < 10) {
    throw new Error("Không tạo được CSI param từ mcp");
  }

  log(socket, `\n[CSI PARAM] ${param}\n`);
  return param;
}

function addHistory(record) {
  captureHistory.unshift(record);
  while (captureHistory.length > 20) captureHistory.pop();
  emitState();
}

function zipCapture(socket, id, rxList) {
  const files = rxList.map(rx => {
    return path.join(CAPTURE_DIR, `${rx.name}_${id}.pcap`);
  });

  const missing = files.filter(file => !fs.existsSync(file));

  if (missing.length) {
    throw new Error(`Thiếu file PCAP: ${missing.map(file => path.basename(file)).join(", ")}`);
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

async function fetchAndZip(socket, rxList, captureId, duration = "") {
  await runAnsible(socket, "ansible/rx_fetch.yml", rxList, {
    capture_id: captureId,
    local_dir: CAPTURE_DIR
  });

  const zipUrl = zipCapture(socket, captureId, rxList);

  rxList.forEach(rx => {
    setRxStatus(rx.name, "configured", "PCAP fetched");
  });

  addHistory({
    id: captureId,
    timestamp: new Date().toISOString(),
    duration,
    rxCount: rxList.length,
    rxNames: rxList.map(rx => rx.name).join(", "),
    status: "fetched",
    zip: zipUrl
  });

  socket.emit("pcap-ready", {
    captureId,
    zipUrl,
    pcapLinks: rxList.map(rx => `/captures/${rx.name}_${captureId}.pcap`)
  });

  return zipUrl;
}

io.on("connection", socket => {
  log(socket, `Connected. Fixed interface = ${IFACE}\n`);
  log(socket, `Capture directory = ${CAPTURE_DIR}\n`);
  emitState(socket);

  socket.on("tx-action", async cfg => {
    try {
      await runTx(socket, cfg.action, cfg);
      notify(socket, "success", `TX ${cfg.action} OK`);
    } catch (err) {
      notify(socket, "error", `TX lỗi: ${err.message}`);
    }
  });

  socket.on("rx-test", async cfg => {
    let rxList;

    try {
      rxList = getRxList(cfg.rxList);
      resetInactiveRxStatus(rxList);

      rxList.forEach(rx => {
        setRxStatus(rx.name, "offline", "Testing SSH...");
      });

      await runAnsible(socket, "ansible/rx_test.yml", rxList);

      rxList.forEach(rx => {
        setRxStatus(rx.name, "online", "SSH OK");
      });

      notify(socket, "success", `Test SSH ${rxList.length} RX OK`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "SSH failed"));
      }

      notify(socket, "error", `RX SSH lỗi: ${err.message}`);
    }
  });

  socket.on("rx-check", async cfg => {
    let rxList;

    try {
      rxList = getRxList(cfg.rxList);
      resetInactiveRxStatus(rxList);

      await runAnsible(socket, "ansible/rx_check.yml", rxList);

      rxList.forEach(rx => {
        setRxStatus(rx.name, "online", "RX tools OK");
      });

      notify(socket, "success", `Check tools ${rxList.length} RX OK`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "RX tools missing"));
      }

      notify(socket, "error", `Check RX tools lỗi: ${err.message}`);
    }
  });

  socket.on("rx-loadfw", async cfg => {
    let rxList;

    try {
      rxList = getRxList(cfg.rxList);
      resetInactiveRxStatus(rxList);

      await runAnsible(socket, "ansible/rx_load_firmware.yml", rxList);

      rxList.forEach(rx => {
        setRxStatus(rx.name, "online", "RX firmware loaded");
      });

      notify(socket, "success", `Load firmware ${rxList.length} RX OK`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "Load firmware failed"));
      }

      notify(socket, "error", `Load RX firmware lỗi: ${err.message}`);
    }
  });

  socket.on("rx-configure", async cfg => {
    let rxList;

    try {
      rxList = getRxList(cfg.rxList);
      resetInactiveRxStatus(rxList);

      const rx = getRxGlobal(cfg);
      const csiParam = await makeCsiParam(socket, rx);

      rxList.forEach(item => {
        setRxStatus(item.name, "online", "Configuring...");
      });

      await runAnsible(socket, "ansible/rx_configure.yml", rxList, {
        channel: rx.channel,
        bandwidth: rx.bandwidth,
        core: rx.core,
        stream: rx.stream,
        csi_param: csiParam
      });

      rxList.forEach(item => {
        setRxStatus(item.name, "configured", `${IFACE} ${rx.channel}/${rx.bandwidth} C${rx.core} S${rx.stream}`);
      });

      notify(socket, "success", `Configure ${rxList.length} RX OK`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "Configure failed"));
      }

      notify(socket, "error", `Configure RX lỗi: ${err.message}`);
    }
  });
  socket.on("rx-verify-tx", async cfg => {
    let rxList;

    try {
      rxList = getRxList(cfg.rxList);
      resetInactiveRxStatus(rxList);

      rxList.forEach(rx => {
        setRxStatus(rx.name, "online", "Verifying TX signal...");
      });

      await runAnsible(socket, "ansible/rx_verify_tx.yml", rxList, {
        verify_seconds: 5,
        min_packets: 5
      });

      rxList.forEach(rx => {
        setRxStatus(rx.name, "configured", "CSI packets detected");
      });

      notify(socket, "success", `RX đã thấy CSI packets. TX đang phát và RX nhận được.`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "No CSI packets detected"));
      }

      notify(socket, "error", `Không thấy CSI packet. Có thể TX chưa phát, sai channel/bandwidth, hoặc RX chưa configure.`);
    }
  });
  socket.on("rx-capture", async cfg => {
    let rxList;

    try {
      rxList = getRxList(cfg.rxList);
      resetInactiveRxStatus(rxList);

      const duration = intRange(cfg.duration, 1, 3600, "Duration");
      const id = makeCaptureId();

      rxList.forEach(rx => {
        setRxStatus(rx.name, "capturing", `${duration}s ID=${id}`);
      });

      await runAnsible(socket, "ansible/rx_capture.yml", rxList, {
        duration,
        capture_id: id
      });

      socket.emit("capture-id", id);

      addHistory({
        id,
        timestamp: new Date().toISOString(),
        duration,
        rxCount: rxList.length,
        rxNames: rxList.map(rx => rx.name).join(", "),
        status: "capturing",
        zip: ""
      });

      notify(socket, "success", `Capture started on ${rxList.length} RX. ID=${id}`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "Capture failed"));
      }

      notify(socket, "error", `Capture lỗi: ${err.message}`);
    }
  });

  socket.on("rx-fetch", async cfg => {
    let rxList;

    try {
      rxList = getRxList(cfg.rxList);
      resetInactiveRxStatus(rxList);

      const id = safeHost(cfg.captureId, "Capture ID");

      await fetchAndZip(socket, rxList, id, cfg.duration || "");

      notify(socket, "success", `Fetch + ZIP OK: ${id}`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "Fetch failed"));
      }

      notify(socket, "error", `Fetch lỗi: ${err.message}`);
    }
  });

  socket.on("full-run", async cfg => {
    let rxList;
    let id = "";

    try {
      const tx = getTx(cfg.tx);
      const rx = getRxGlobal(cfg.rx);
      rxList = getRxList(cfg.rxList);

      checkTxRxIpConflict(tx, rxList);
      resetInactiveRxStatus(rxList);

      id = makeCaptureId();

      notify(socket, "info", "Full Run: check/load/configure TX...");
      await runTx(socket, "check", tx);
      await runTx(socket, "loadfw", tx);
      await runTx(socket, "configure", tx);

      notify(socket, "info", `Full Run: check/load/configure ${rxList.length} RX...`);
      await runAnsible(socket, "ansible/rx_check.yml", rxList);
      await runAnsible(socket, "ansible/rx_load_firmware.yml", rxList);

      const csiParam = await makeCsiParam(socket, rx);

      await runAnsible(socket, "ansible/rx_configure.yml", rxList, {
        channel: rx.channel,
        bandwidth: rx.bandwidth,
        core: rx.core,
        stream: rx.stream,
        csi_param: csiParam
      });

      rxList.forEach(item => {
        setRxStatus(item.name, "configured", `${IFACE} ${rx.channel}/${rx.bandwidth}`);
      });

      notify(socket, "info", "Full Run: start capture...");

      rxList.forEach(item => {
        setRxStatus(item.name, "capturing", `${rx.duration}s ID=${id}`);
      });

      await runAnsible(socket, "ansible/rx_capture.yml", rxList, {
        duration: rx.duration,
        capture_id: id
      });

      socket.emit("capture-id", id);

      notify(socket, "info", "Full Run: init/start TX...");
      await runTx(socket, "init", tx);
      await sleep(500);
      await runTx(socket, "start", tx);

      addHistory({
        id,
        timestamp: new Date().toISOString(),
        duration: rx.duration,
        rxCount: rxList.length,
        rxNames: rxList.map(rx => rx.name).join(", "),
        status: "capturing",
        zip: ""
      });

      notify(socket, "info", `Đang thu ${rx.duration}s trên ${rxList.length} RX...`);
      await sleep(rx.duration * 1000 + 2000);

      notify(socket, "info", "Full Run: stop TX...");
      await runTx(socket, "stop", tx);

      notify(socket, "info", "Full Run: fetch + zip PCAP...");
      const zipUrl = await fetchAndZip(socket, rxList, id, rx.duration);

      notify(socket, "success", `Full Run hoàn tất. ZIP: ${zipUrl}`);
    } catch (err) {
      if (rxList) {
        rxList.forEach(rx => setRxStatus(rx.name, "error", "Full Run failed"));
      }

      notify(socket, "error", `Full Run lỗi: ${err.message}`);

      try {
        if (cfg.tx) {
          await runTx(socket, "stop", cfg.tx);
        }
      } catch {}
    }
  });
});

server.listen(PORT, () => {
  console.log(`CSI Web Terminal running at http://localhost:${PORT}`);
  console.log(`Capture folder: ${CAPTURE_DIR}`);
});
