var DB_FILE = "vpncache.db";
var API_BASE = "https://proxycheck.io/v3/";
var ACTIONS = ["report", "warn", "kick", "ban", "muzzle"];
var FLAGS = ["proxy", "vpn", "tor", "hosting", "anonymous"];

var DEFAULT_CFG = {
    enabled: false,
    action: "report",
    ttlDays: 30,
    dailyLimit: 950,
    flagProxy: true,
    flagVpn: true,
    flagTor: true,
    flagHosting: false,
    flagAnonymous: false,
    apiKey: "",
    notifyMessage: "Desactivá tu VPN/proxy para poder entrar."
};

var CFG = {};
var __inflight = {};
var __lastCleanup = 0;

function nowSecs() {
    try { return Math.floor(Date.now() / 1000); } catch (e) {}
    try { return Math.floor(tickCount() / 1000); } catch (e) {}
    return 0;
}

function pad2(n) { return n < 10 ? "0" + n : "" + n; }

function today() {
    var d = new Date();
    return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate());
}

function vlog(msg) {
    try { log("[vpncheck] " + msg); } catch (e) {}
}

function sendTo(name, text) {
    if (!name) return;
    var u = user("" + name);
    if (u != null) { try { u.sendPM("" + text); } catch (e) {} }
}

function getUser(n) {
    if (n == null || n === "") return null;
    var u = user("" + n);
    if (u != null && u.exists && u.exists()) return u;
    return null;
}

function openDb() {
    var db = new Sql();
    if (!db.open(DB_FILE)) {
        vlog("no se pudo abrir " + DB_FILE + ": " + db.lastError);
        return null;
    }
    return db;
}

function ensureDb() {
    var db = openDb();
    if (db == null) return false;
    db.query(new Query("CREATE TABLE IF NOT EXISTS vpn_cache (ip TEXT NOT NULL, guid TEXT NOT NULL, is_vpn INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL DEFAULT '', checked_at INTEGER NOT NULL, PRIMARY KEY (ip, guid))"));
    db.query(new Query("CREATE TABLE IF NOT EXISTS usage (day TEXT PRIMARY KEY, queries INTEGER NOT NULL)"));
    db.query(new Query("CREATE TABLE IF NOT EXISTS detections (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, guid TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL, action TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL DEFAULT '', detected_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active')"));
    db.query(new Query("CREATE TABLE IF NOT EXISTS whitelist (ip TEXT PRIMARY KEY, guid TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', added_at INTEGER NOT NULL)"));
    db.close();
    return true;
}

function loadConfig() {
    CFG = {};
    var k;
    for (k in DEFAULT_CFG) {
        if (Object.prototype.hasOwnProperty.call(DEFAULT_CFG, k)) CFG[k] = DEFAULT_CFG[k];
    }
    var bools = ["enabled", "flagProxy", "flagVpn", "flagTor", "flagHosting", "flagAnonymous"];
    var ints = ["ttlDays", "dailyLimit"];
    var strs = ["action", "apiKey", "notifyMessage"];
    var i;
    for (i = 0; i < bools.length; i++) {
        var b = bools[i];
        if (Registry.exists(b)) CFG[b] = ("" + Registry.getValue(b)) === "true";
    }
    for (i = 0; i < ints.length; i++) {
        var n = ints[i];
        if (Registry.exists(n)) {
            var iv = parseInt(Registry.getValue(n), 10);
            if (!isNaN(iv)) CFG[n] = iv;
        }
    }
    for (i = 0; i < strs.length; i++) {
        var s = strs[i];
        if (Registry.exists(s)) CFG[s] = "" + Registry.getValue(s);
    }
    if (!(CFG.ttlDays >= 0)) CFG.ttlDays = 30;
    if (!(CFG.dailyLimit > 0)) CFG.dailyLimit = 950;
    if (ACTIONS.indexOf(CFG.action) < 0) CFG.action = "report";
}

function saveConfig() {
    Registry.setValue("enabled", CFG.enabled ? "true" : "false");
    Registry.setValue("action", CFG.action);
    Registry.setValue("ttlDays", "" + CFG.ttlDays);
    Registry.setValue("dailyLimit", "" + CFG.dailyLimit);
    Registry.setValue("flagProxy", CFG.flagProxy ? "true" : "false");
    Registry.setValue("flagVpn", CFG.flagVpn ? "true" : "false");
    Registry.setValue("flagTor", CFG.flagTor ? "true" : "false");
    Registry.setValue("flagHosting", CFG.flagHosting ? "true" : "false");
    Registry.setValue("flagAnonymous", CFG.flagAnonymous ? "true" : "false");
    Registry.setValue("apiKey", CFG.apiKey);
    Registry.setValue("notifyMessage", CFG.notifyMessage);
}

function onLoad() {
    try {
        loadConfig();
        if (!ensureDb()) return;
        try { Help_addLine("proxy", "/proxy - filtro VPN/proxy (proxycheck.io)"); } catch (e) {}
    } catch (e) {
        log("[vpncheck] error al iniciar: " + e);
        return;
    }
    vlog("cargado (enabled=" + CFG.enabled + ", action=" + CFG.action + ", apiKey=" + (CFG.apiKey ? "sí" : "NO") + ")");
}

function isIp(s) {
    if (!s) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return true;
    if (s.indexOf(":") >= 0 && /^[0-9a-fA-F:]+$/.test(s)) return true;
    return false;
}

function isFresh(checkedAt) {
    if (CFG.ttlDays <= 0) return true;
    return (nowSecs() - checkedAt) < (CFG.ttlDays * 86400);
}

function isWhitelisted(ip, guid) {
    var db = openDb();
    if (db == null) return false;
    var hit = false;
    var hasGuid = guid && guid !== "null" && guid !== "undefined" && guid.length > 0;
    if (hasGuid) db.query(new Query("SELECT ip FROM whitelist WHERE ip=? OR (guid<>'' AND guid=?)", ip, guid));
    else db.query(new Query("SELECT ip FROM whitelist WHERE ip=?", ip));
    if (db.canRead) hit = true;
    db.close();
    return hit;
}

function getCache(ip, guid) {
    var db = openDb();
    if (db == null) return null;
    db.query(new Query("SELECT is_vpn, kind, provider, checked_at FROM vpn_cache WHERE ip=? AND guid=?", ip, guid));
    var out = null;
    if (db.canRead) {
        out = {
            is_vpn: ("" + db.value("is_vpn")) === "1",
            kind: "" + db.value("kind"),
            provider: "" + db.value("provider"),
            checked_at: parseInt(db.value("checked_at"), 10) || 0
        };
    }
    db.close();
    return out;
}

function saveCache(ip, guid, isVpn, kind, provider) {
    var db = openDb();
    if (db == null) return;
    db.query(new Query("INSERT OR REPLACE INTO vpn_cache (ip, guid, is_vpn, kind, provider, checked_at) VALUES (?,?,?,?,?,?)", ip, guid, isVpn ? 1 : 0, "" + kind, "" + provider, nowSecs()));
    db.close();
}

function todayQueries() {
    var db = openDb();
    if (db == null) return 0;
    db.query(new Query("SELECT queries FROM usage WHERE day=?", today()));
    var n = 0;
    if (db.canRead) n = parseInt(db.value("queries"), 10) || 0;
    db.close();
    return n;
}

function bumpUsage() {
    var db = openDb();
    if (db == null) return;
    db.query(new Query("INSERT INTO usage (day, queries) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET queries = queries + 1", today()));
    db.close();
}

function detectKind(det) {
    if (det == null) return "";
    if (CFG.flagProxy && det.proxy === true) return "proxy";
    if (CFG.flagVpn && det.vpn === true) return "vpn";
    if (CFG.flagTor && det.tor === true) return "tor";
    if (CFG.flagHosting && det.hosting === true) return "hosting";
    if (CFG.flagAnonymous && det.anonymous === true) return "anonymous";
    return "";
}

function recordDetection(name, guid, ip, action, kind, provider) {
    var db = openDb();
    if (db == null) return;
    db.query(new Query("SELECT id FROM detections WHERE guid=? AND ip=? AND status='active'", guid, ip));
    if (db.canRead) {
        var id = parseInt(db.value("id"), 10) || 0;
        db.query(new Query("UPDATE detections SET name=?, action=?, kind=?, provider=?, detected_at=? WHERE id=?", name, action, kind, provider, nowSecs(), id));
    } else {
        db.query(new Query("INSERT INTO detections (name, guid, ip, action, kind, provider, detected_at, status) VALUES (?,?,?,?,?,?,?,'active')", name, guid, ip, action, kind, provider, nowSecs()));
    }
    db.close();
}

function applyAction(user) {
    var act = CFG.action;
    if (act === "report") return;
    if (act === "warn") {
        try { user.sendPM(CFG.notifyMessage); } catch (e) {}
        return;
    }
    if (CFG.notifyMessage) {
        try { user.sendPM(CFG.notifyMessage); } catch (e) {}
    }
    if (act === "muzzle") { try { user.muzzled = true; } catch (e) {} return; }
    if (act === "kick") { try { user.kick(); } catch (e) {} return; }
    if (act === "ban") { try { user.ban(); } catch (e) {} return; }
}

function enforce(user, ip, guid, kind, provider, source) {
    if (user == null) return;
    var name = "" + user.name;
    vlog("detectado (" + source + "): " + name + " ip=" + ip + " kind=" + kind + " provider=" + provider + " action=" + CFG.action);
    recordDetection(name, guid, ip, CFG.action, kind, provider);
    applyAction(user);
}

function queryProxycheck(user, ip, guid) {
    var key = ip + "|" + guid;
    var r = new HttpRequest();
    r.method = "GET";
    r.src = API_BASE + ip + "?key=" + encodeURIComponent(CFG.apiKey) + "&tag=astra&p=0";
    r.utf = true;
    r.userAgent = "Astra-vpncheck";
    r.oncomplete = function(body, status, error) {
        delete __inflight[key];
        bumpUsage();
        if (status !== 200 || !body) {
            vlog("proxycheck error ip=" + ip + " status=" + status + " error=" + error);
            return;
        }
        var j = null;
        try { j = JSON.parse("" + body); } catch (e) { vlog("proxycheck JSON inválido: " + e); return; }
        var st = (j && j.status) ? ("" + j.status) : "";
        if (st === "denied" || st === "error") {
            vlog("proxycheck " + st + " para " + ip + ": " + (j && j.message ? j.message : ""));
            return;
        }
        if (st === "warning") vlog("proxycheck aviso para " + ip + ": " + (j && j.message ? j.message : ""));
        var ipKey = (j && j.ip) ? ("" + j.ip) : ip;
        var node = j != null ? (j[ipKey] || j[ip]) : null;
        if (!node) { vlog("proxycheck: respuesta sin datos para " + ip); return; }
        var det = node.detections || {};
        var net = node.network || {};
        var provider = net.provider || net.organisation || "";
        var kind = detectKind(det);
        saveCache(ip, guid, kind !== "", kind, provider);
        if (kind !== "" && CFG.enabled) enforce(user, ip, guid, kind, provider, "api");
    };
    if (!r.download()) {
        delete __inflight[key];
        vlog("no se pudo iniciar la consulta de " + ip);
        return;
    }
    vlog("consultando proxycheck: " + ip);
}

function onJoin(user, ip) {
    try {
        if (!CFG.enabled || user == null) return;
        var ipStr = "" + (ip || user.externalIp);
        if (!ipStr) return;
        var guid = "" + user.guid;
        if (isWhitelisted(ipStr, guid)) return;
        var cached = getCache(ipStr, guid);
        if (cached != null && isFresh(cached.checked_at)) {
            if (cached.is_vpn) enforce(user, ipStr, guid, cached.kind, cached.provider, "cache");
            return;
        }
        if (!CFG.apiKey) return;
        if (todayQueries() >= CFG.dailyLimit) {
            vlog("límite diario alcanzado (" + CFG.dailyLimit + "), se omite " + ipStr);
            return;
        }
        var key = ipStr + "|" + guid;
        if (__inflight[key]) return;
        __inflight[key] = true;
        queryProxycheck(user, ipStr, guid);
    } catch (e) {
        vlog("error en onJoin: " + e);
    }
}

function onTimer() {
    try {
        var now = nowSecs();
        if (__lastCleanup !== 0 && (now - __lastCleanup) < 86400) return;
        __lastCleanup = now;
        if (CFG.ttlDays > 0) {
            var db = openDb();
            if (db != null) {
                db.query(new Query("DELETE FROM vpn_cache WHERE checked_at < ?", now - (CFG.ttlDays * 86400)));
                db.close();
            }
        }
    } catch (e) {}
}

function findDetectionByIp(ip) {
    var db = openDb();
    if (db == null) return null;
    db.query(new Query("SELECT name, guid, ip FROM detections WHERE ip=? ORDER BY detected_at DESC LIMIT 1", ip));
    var out = null;
    if (db.canRead) out = { name: "" + db.value("name"), ip: "" + db.value("ip"), guid: "" + db.value("guid") };
    db.close();
    return out;
}

function findDetectionByName(name) {
    var db = openDb();
    if (db == null) return null;
    db.query(new Query("SELECT name, guid, ip FROM detections WHERE lower(name)=lower(?) ORDER BY detected_at DESC LIMIT 1", name));
    var out = null;
    if (db.canRead) out = { name: "" + db.value("name"), ip: "" + db.value("ip"), guid: "" + db.value("guid") };
    db.close();
    return out;
}

function findOnlineByIp(ip) {
    var list = Users.userNames();
    for (var i = 0; i < list.length; i++) {
        var u = getUser(list[i]);
        if (u != null && ("" + u.externalIp) === ip) return u;
    }
    return null;
}

function resolveTarget(q) {
    var s = "" + q;
    if (isIp(s)) {
        var det = findDetectionByIp(s);
        if (det != null) return det;
        var on = findOnlineByIp(s);
        if (on != null) return { name: "" + on.name, ip: s, guid: "" + on.guid };
        return { name: "", ip: s, guid: "" };
    }
    var live = getUser(s);
    if (live != null) return { name: "" + live.name, ip: "" + live.externalIp, guid: "" + live.guid };
    return findDetectionByName(s);
}

function unbanMatches(name, ip) {
    var arr = Users.banned();
    var n = 0;
    var lname = name ? name.toLowerCase() : "";
    for (var i = 0; i < arr.length; i++) {
        var b = arr[i];
        var bname = ("" + (b.name || "")).toLowerCase();
        var bip = "" + (b.externalIp || "");
        if ((lname && bname === lname) || (ip && bip === ip)) {
            if (b.unban()) n++;
        }
    }
    return n > 0;
}

function showHelp(user) {
    var n = "" + user.name;
    sendTo(n, "=== vpncheck: /proxy ===");
    sendTo(n, "/proxy status | on | off");
    sendTo(n, "/proxy action " + ACTIONS.join("|"));
    sendTo(n, "/proxy ttl <días> | limit <n> | key <apiKey>");
    sendTo(n, "/proxy flag <" + FLAGS.join("|") + "> <on|off>");
    sendTo(n, "/proxy msg <texto>");
    sendTo(n, "/proxy list [active|all] | info <nick|ip>");
    sendTo(n, "/proxy release <nick|ip> | allow <nick|ip>");
    sendTo(n, "/proxy whitelist add|del|list [ip]");
    sendTo(n, "/proxy check <ip> | cache stats|clear [ip|all]");
}

function showStatus(user) {
    var n = "" + user.name;
    sendTo(n, "=== vpncheck ===");
    sendTo(n, "enabled=" + CFG.enabled + " | action=" + CFG.action + " | ttl=" + (CFG.ttlDays === 0 ? "permanente" : CFG.ttlDays + "d"));
    sendTo(n, "consultas hoy=" + todayQueries() + "/" + CFG.dailyLimit + " | apiKey=" + (CFG.apiKey ? "sí" : "NO"));
    sendTo(n, "flags: proxy=" + CFG.flagProxy + " vpn=" + CFG.flagVpn + " tor=" + CFG.flagTor + " hosting=" + CFG.flagHosting + " anonymous=" + CFG.flagAnonymous);
    sendTo(n, "msg: " + CFG.notifyMessage);
}

function listDetections(user, rest) {
    var onlyActive = ("" + rest).toLowerCase() !== "all";
    var db = openDb();
    if (db == null) return;
    if (onlyActive) db.query(new Query("SELECT id, name, ip, action, kind, status FROM detections WHERE status='active' ORDER BY detected_at DESC LIMIT 25"));
    else db.query(new Query("SELECT id, name, ip, action, kind, status FROM detections ORDER BY detected_at DESC LIMIT 25"));
    sendTo("" + user.name, onlyActive ? "=== detectados activos (máx 25) ===" : "=== detectados (máx 25) ===");
    var n = 0;
    while (db.canRead) {
        var online = (getUser(db.value("name")) != null) ? "online" : "-";
        sendTo("" + user.name, "#" + db.value("id") + " " + db.value("name") + " [" + db.value("ip") + "] " + db.value("action") + "/" + db.value("kind") + " " + db.value("status") + " " + online);
        n++;
    }
    if (n === 0) sendTo("" + user.name, "(sin detecciones)");
    db.close();
}

function infoDetection(user, rest) {
    var q = ("" + rest).replace(/^\s+|\s+$/g, "");
    if (!q) { sendTo("" + user.name, "Uso: /proxy info <nick|ip>"); return; }
    var db = openDb();
    if (db == null) return;
    db.query(new Query("SELECT name, guid, ip, action, kind, provider, detected_at, status FROM detections WHERE lower(name)=lower(?) OR ip=? ORDER BY detected_at DESC LIMIT 1", q, q));
    if (!db.canRead) {
        sendTo("" + user.name, "No hay detecciones para " + q + ".");
        db.close();
        return;
    }
    sendTo("" + user.name, "name=" + db.value("name") + " guid=" + db.value("guid"));
    sendTo("" + user.name, "ip=" + db.value("ip") + " action=" + db.value("action") + " kind=" + db.value("kind"));
    sendTo("" + user.name, "provider=" + db.value("provider") + " status=" + db.value("status") + " detected_at=" + db.value("detected_at"));
    db.close();
}

function releaseOne(user, rest, alsoWhitelist) {
    var q = ("" + rest).replace(/^\s+|\s+$/g, "");
    if (!q) {
        sendTo("" + user.name, "Uso: /proxy " + (alsoWhitelist ? "allow" : "release") + " <nick|ip>");
        return;
    }
    var t = resolveTarget(q);
    if (t == null) { sendTo("" + user.name, "No encontré '" + q + "'."); return; }
    var unbanned = unbanMatches(t.name, t.ip);
    var unmuzzled = false;
    if (t.name) {
        var online = getUser(t.name);
        if (online != null) {
            try { online.muzzled = false; unmuzzled = true; } catch (e) {}
        }
    }
    var db = openDb();
    if (db != null) {
        if (t.ip) db.query(new Query("UPDATE detections SET status='released' WHERE (ip=? OR lower(name)=lower(?)) AND status='active'", t.ip, t.name));
        else db.query(new Query("UPDATE detections SET status='released' WHERE lower(name)=lower(?) AND status='active'", t.name));
        if (t.ip) db.query(new Query("DELETE FROM vpn_cache WHERE ip=?", t.ip));
        if (alsoWhitelist && t.ip) {
            db.query(new Query("INSERT OR REPLACE INTO whitelist (ip, guid, note, added_at) VALUES (?,?,?,?)", t.ip, t.guid || "", "allowed by " + user.name, nowSecs()));
        }
        db.close();
    }
    var label = t.name ? t.name : t.ip;
    sendTo("" + user.name, "Liberado " + label + (unbanned ? " [unban]" : "") + (unmuzzled ? " [unmute]" : "") + (alsoWhitelist ? " [whitelist]" : ""));
}

function handleWhitelist(user, rest) {
    var parts = ("" + rest).split(/\s+/);
    var op = (parts.length && parts[0]) ? parts[0].toLowerCase() : "list";
    var arg = parts.length > 1 ? parts[1] : "";
    var db = openDb();
    if (db == null) return;
    if (op === "add") {
        if (!isIp(arg)) { sendTo("" + user.name, "IP inválida."); db.close(); return; }
        db.query(new Query("INSERT OR REPLACE INTO whitelist (ip, guid, note, added_at) VALUES (?,?,?,?)", arg, "", "manual " + user.name, nowSecs()));
        sendTo("" + user.name, "IP " + arg + " agregada a la whitelist.");
    } else if (op === "del" || op === "delete" || op === "remove") {
        db.query(new Query("DELETE FROM whitelist WHERE ip=?", arg));
        sendTo("" + user.name, "IP " + arg + " quitada de la whitelist.");
    } else {
        db.query(new Query("SELECT ip, guid, note FROM whitelist ORDER BY added_at DESC LIMIT 50"));
        var n = 0;
        while (db.canRead) {
            sendTo("" + user.name, db.value("ip") + (db.value("guid") ? " guid=" + db.value("guid") : "") + " (" + db.value("note") + ")");
            n++;
        }
        if (n === 0) sendTo("" + user.name, "(whitelist vacía)");
    }
    db.close();
}

function handleCache(user, rest) {
    var parts = ("" + rest).split(/\s+/);
    var op = (parts.length && parts[0]) ? parts[0].toLowerCase() : "stats";
    var arg = parts.length > 1 ? parts[1] : "";
    var db = openDb();
    if (db == null) return;
    if (op === "clear") {
        if (arg === "all" || arg === "") {
            db.query(new Query("DELETE FROM vpn_cache"));
            sendTo("" + user.name, "Cache vaciado.");
        } else {
            db.query(new Query("DELETE FROM vpn_cache WHERE ip=?", arg));
            sendTo("" + user.name, "Cache borrado para " + arg + ".");
        }
    } else {
        var total = 0, vpns = 0, active = 0, wl = 0;
        db.query(new Query("SELECT COUNT(*) AS n FROM vpn_cache"));
        if (db.canRead) total = parseInt(db.value("n"), 10) || 0;
        db.query(new Query("SELECT COUNT(*) AS n FROM vpn_cache WHERE is_vpn=1"));
        if (db.canRead) vpns = parseInt(db.value("n"), 10) || 0;
        db.query(new Query("SELECT COUNT(*) AS n FROM detections WHERE status='active'"));
        if (db.canRead) active = parseInt(db.value("n"), 10) || 0;
        db.query(new Query("SELECT COUNT(*) AS n FROM whitelist"));
        if (db.canRead) wl = parseInt(db.value("n"), 10) || 0;
        sendTo("" + user.name, "cache=" + total + " (vpn=" + vpns + ") | activos=" + active + " | whitelist=" + wl + " | hoy=" + todayQueries() + "/" + CFG.dailyLimit);
    }
    db.close();
}

function manualCheck(adminName, ip) {
    if (!CFG.apiKey) { sendTo(adminName, "Falta la API key (/proxy key <key>)."); return; }
    if (todayQueries() >= CFG.dailyLimit) { sendTo(adminName, "Límite diario alcanzado (" + CFG.dailyLimit + ")."); return; }
    var r = new HttpRequest();
    r.method = "GET";
    r.src = API_BASE + ip + "?key=" + encodeURIComponent(CFG.apiKey) + "&tag=astra-manual&p=0";
    r.utf = true;
    r.userAgent = "Astra-vpncheck";
    r.oncomplete = function(body, status, error) {
        bumpUsage();
        if (status !== 200 || !body) { sendTo(adminName, "proxycheck error status=" + status + " error=" + error); return; }
        var j = null;
        try { j = JSON.parse("" + body); } catch (e) { sendTo(adminName, "JSON inválido: " + e); return; }
        var st = (j && j.status) ? ("" + j.status) : "";
        if (st === "denied" || st === "error") { sendTo(adminName, "proxycheck " + st + ": " + (j && j.message ? j.message : "")); return; }
        var ipKey = (j && j.ip) ? ("" + j.ip) : ip;
        var node = j != null ? (j[ipKey] || j[ip]) : null;
        if (!node) { sendTo(adminName, "Sin datos para " + ip); return; }
        var det = node.detections || {};
        var net = node.network || {};
        var kind = detectKind(det);
        sendTo(adminName, "proxycheck " + ip + ": " + (kind !== "" ? "BLOQUEADO (" + kind + ")" : "limpio") + " | red=" + (net.type || "?") + " | provider=" + (net.provider || net.organisation || "?") + " | confidence=" + (det.confidence != null ? det.confidence : "?"));
    };
    if (!r.download()) { sendTo(adminName, "No se pudo iniciar la consulta."); return; }
    sendTo(adminName, "Consultando " + ip + "...");
}

function handleSub(user, sub, rest) {
    var n = "" + user.name;
    if (sub === "status" || sub === "") { showStatus(user); return; }
    if (sub === "help") { showHelp(user); return; }
    if (sub === "on") { CFG.enabled = true; saveConfig(); sendTo(n, "vpncheck activado."); return; }
    if (sub === "off") { CFG.enabled = false; saveConfig(); sendTo(n, "vpncheck desactivado."); return; }
    if (sub === "action") {
        var a = ("" + rest).toLowerCase();
        if (ACTIONS.indexOf(a) < 0) { sendTo(n, "Acción inválida. Opciones: " + ACTIONS.join(", ")); return; }
        CFG.action = a; saveConfig(); sendTo(n, "Acción = " + a); return;
    }
    if (sub === "ttl") {
        var t = parseInt(rest, 10);
        if (isNaN(t) || t < 0) { sendTo(n, "TTL inválido (días, 0 = permanente)."); return; }
        CFG.ttlDays = t; saveConfig(); sendTo(n, "TTL = " + (t === 0 ? "permanente" : t + " días") + "."); return;
    }
    if (sub === "limit") {
        var lim = parseInt(rest, 10);
        if (isNaN(lim) || lim <= 0) { sendTo(n, "Límite inválido."); return; }
        CFG.dailyLimit = lim; saveConfig(); sendTo(n, "Límite diario = " + lim); return;
    }
    if (sub === "flag") {
        var fp = ("" + rest).split(/\s+/);
        if (fp.length < 2) { sendTo(n, "Uso: /proxy flag <" + FLAGS.join("|") + "> <on|off>"); return; }
        var fname = fp[0].toLowerCase();
        var fon = fp[1].toLowerCase();
        if (FLAGS.indexOf(fname) < 0) { sendTo(n, "Flag inválida: " + fname); return; }
        if (fon !== "on" && fon !== "off") { sendTo(n, "Usá on u off."); return; }
        var field = "flag" + fname.charAt(0).toUpperCase() + fname.slice(1);
        CFG[field] = (fon === "on");
        saveConfig(); sendTo(n, fname + " = " + fon); return;
    }
    if (sub === "msg") {
        if (!rest) { sendTo(n, "Uso: /proxy msg <texto>"); return; }
        CFG.notifyMessage = "" + rest; saveConfig(); sendTo(n, "Mensaje actualizado."); return;
    }
    if (sub === "key") {
        if (!rest) { sendTo(n, "Uso: /proxy key <apiKey>"); return; }
        CFG.apiKey = ("" + rest).replace(/^\s+|\s+$/g, ""); saveConfig(); sendTo(n, "API key guardada."); return;
    }
    if (sub === "list") { listDetections(user, rest); return; }
    if (sub === "info") { infoDetection(user, rest); return; }
    if (sub === "release") { releaseOne(user, rest, false); return; }
    if (sub === "allow") { releaseOne(user, rest, true); return; }
    if (sub === "whitelist") { handleWhitelist(user, rest); return; }
    if (sub === "check") {
        var ip = ("" + rest).replace(/^\s+|\s+$/g, "");
        if (!isIp(ip)) { sendTo(n, "Uso: /proxy check <ip>"); return; }
        manualCheck(n, ip); return;
    }
    if (sub === "cache") { handleCache(user, rest); return; }
    sendTo(n, "Subcomando desconocido: " + sub + ". Probá /proxy help");
}

function onCommand(user, command, target, args) {
    try {
        if (user == null) return;
        var full = "" + command;
        var cmdName = full.split(/\s+/)[0].toLowerCase();
        if (cmdName !== "proxy") return;
        if (user.level < 2) { sendTo("" + user.name, "Access denied."); return; }
        var raw = ("" + args).replace(/^\s+|\s+$/g, "");
        var parts = raw.length ? raw.split(/\s+/) : [];
        var sub = parts.length ? parts[0].toLowerCase() : "status";
        var rest = parts.length > 1 ? parts.slice(1).join(" ") : "";
        handleSub(user, sub, rest);
    } catch (e) {
        vlog("error en onCommand: " + e);
    }
}
