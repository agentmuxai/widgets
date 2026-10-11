#!/usr/bin/env node
// Copyright 2026, AgentMux Corp.
// SPDX-License-Identifier: Apache-2.0

/**
 * Builds the AgentMux widget catalog: checks every widget under widgets/,
 * then writes dist/index.json, one zip per widget, and (on main, with the
 * catalog key) dist/index.json.sig.
 *
 *   node scripts/build.mjs [--out dist] [--base-url https://agentmuxai.github.io/widgets]
 *
 * With CATALOG_SIGNING_SEED (base64, 32 bytes) set, the index is signed.
 * AgentMux checks every rule here again when it installs a widget: this is
 * the catalog's own gate, not the last one.
 *
 * The rules (SPEC_WIDGET_SHARING_2026_10_10.md §4.4):
 *   - the folder is named as the widget's id; the manifest is version 1,
 *     sandboxed, semver, with its entry files present;
 *   - it is signed (widget.sig), the signature matches its files, and the key
 *     is the one publishers.json lists for its publisher;
 *   - at most 50 MB and 2,000 files, no links;
 *   - no script or stylesheet from another origin in its HTML.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const SIG_FILE = "widget.sig";
const CONTEXT = "agentmux-widget-sig-v1\0";
const MAX_BYTES = 50 * 1024 * 1024;
const MAX_FILES = 2000;
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ID = /^[a-z0-9-]+\.[a-z0-9-]+$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

const arg = (name, fallback) => {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : fallback;
};
const OUT = arg("--out", "dist");
const BASE_URL = arg("--base-url", "https://agentmuxai.github.io/widgets").replace(/\/$/, "");

/** relative path → bytes, every file but widget.sig, as AgentMux reads a package. */
function readPackage(dir) {
    const files = new Map();
    let total = 0;
    const walk = (abs, rel) => {
        for (const name of readdirSync(abs)) {
            const p = join(abs, name);
            const r = rel ? `${rel}/${name}` : name;
            const st = lstatSync(p);
            if (st.isSymbolicLink()) throw new Error(`${r} is a link`);
            if (st.isDirectory()) {
                walk(p, r);
                continue;
            }
            if (r === SIG_FILE) continue;
            const bytes = readFileSync(p);
            total += bytes.length;
            if (total > MAX_BYTES) throw new Error("over 50 MB");
            files.set(r, bytes);
            if (files.size > MAX_FILES) throw new Error(`over ${MAX_FILES} files`);
        }
    };
    walk(dir, "");
    return files;
}

/** AgentMux's content hash (SPEC_USER_WIDGETS_AND_WIDGET_API §8.2). */
function packageHash(files) {
    const h = createHash("sha256");
    for (const path of [...files.keys()].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
        h.update(path).update("\0").update(createHash("sha256").update(files.get(path)).digest("hex")).update("\n");
    }
    return h.digest("hex");
}

function publicKeyOf(b64) {
    return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(b64, "base64")]), format: "der", type: "spki" });
}

function checkWidget(dir, folder, publishers) {
    const files = readPackage(dir);
    const manifest = JSON.parse(files.get("widget.json")?.toString("utf8") ?? "null");
    if (!manifest) throw new Error("no widget.json");
    if (manifest.manifestVersion !== 1) throw new Error("manifestVersion must be 1");
    if (!ID.test(manifest.id ?? "") || manifest.id !== folder) throw new Error(`id must be publisher.name and match the folder (${folder})`);
    if (!SEMVER.test(manifest.version ?? "")) throw new Error("version must be semver");
    if ((manifest.kind ?? "sandboxed") !== "sandboxed") throw new Error("the catalog lists sandboxed widgets only");
    if (typeof manifest.name !== "string" || !manifest.name.trim()) throw new Error("needs a name");
    const panes = manifest.contributes?.panes ?? [];
    if (!panes.length) throw new Error("contributes.panes must list a pane");
    for (const p of panes) {
        const entry = p.entry ?? manifest.entry ?? "index.html";
        if (!files.has(entry)) throw new Error(`its entry ${entry} isn't in the package`);
    }
    for (const [path, bytes] of files) {
        if (!/\.html?$/.test(path)) continue;
        const html = bytes.toString("utf8");
        if (/<script[^>]+src=["']?\s*(https?:)?\/\//i.test(html) || /<link[^>]+href=["']?\s*(https?:)?\/\//i.test(html)) {
            throw new Error(`${path} loads a script or stylesheet from another origin`);
        }
    }
    const hash = packageHash(files);
    const sig = JSON.parse(readFileSync(join(dir, SIG_FILE), "utf8"));
    if (sig.sigVersion !== 1 || sig.algorithm !== "ed25519") throw new Error("widget.sig isn't a version 1 ed25519 signature");
    const publisher = manifest.id.split(".")[0];
    if (!publishers[publisher]) throw new Error(`publisher ${publisher} isn't in publishers.json: add your key there in this PR`);
    if (publishers[publisher] !== sig.publicKey) throw new Error(`signed by another key than the one publishers.json lists for ${publisher}`);
    const message = Buffer.from(`${CONTEXT}${manifest.id}\0${manifest.version}\0${hash}`);
    if (!verify(null, message, publicKeyOf(sig.publicKey), Buffer.from(sig.signature, "base64"))) {
        throw new Error("its signature doesn't match its files: sign it again after the last edit");
    }
    files.set(SIG_FILE, readFileSync(join(dir, SIG_FILE)));
    return { manifest, hash, files, publicKey: sig.publicKey };
}

// ── A small, deterministic zip writer (stored entries) ─────────────────────

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
});
function crc32(buf) {
    let c = 0xffffffff;
    for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}

/** A zip of `files` (name → bytes) under `root/`, in name order, fixed times. */
function zip(root, files) {
    const local = [];
    const central = [];
    let offset = 0;
    for (const name of [...files.keys()].sort()) {
        const data = files.get(name);
        const path = Buffer.from(`${root}/${name}`, "utf8");
        const crc = crc32(data);
        const head = Buffer.alloc(30);
        head.writeUInt32LE(0x04034b50, 0);
        head.writeUInt16LE(20, 4);
        head.writeUInt16LE(0x0800, 6); // UTF-8 names
        head.writeUInt16LE(0, 8); // stored
        head.writeUInt16LE(0, 10);
        head.writeUInt16LE(0x21, 12); // 1980-01-01
        head.writeUInt32LE(crc, 14);
        head.writeUInt32LE(data.length, 18);
        head.writeUInt32LE(data.length, 22);
        head.writeUInt16LE(path.length, 26);
        head.writeUInt16LE(0, 28);
        local.push(head, path, data);
        const dir = Buffer.alloc(46);
        dir.writeUInt32LE(0x02014b50, 0);
        dir.writeUInt16LE(20, 4);
        dir.writeUInt16LE(20, 6);
        dir.writeUInt16LE(0x0800, 8);
        dir.writeUInt16LE(0, 10);
        dir.writeUInt16LE(0, 12);
        dir.writeUInt16LE(0x21, 14);
        dir.writeUInt32LE(crc, 16);
        dir.writeUInt32LE(data.length, 20);
        dir.writeUInt32LE(data.length, 24);
        dir.writeUInt16LE(path.length, 28);
        dir.writeUInt32LE(offset, 42);
        central.push(dir, path);
        offset += head.length + path.length + data.length;
    }
    const centralBytes = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(files.size, 8);
    end.writeUInt16LE(files.size, 10);
    end.writeUInt32LE(centralBytes.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...local, centralBytes, end]);
}

// ── Build ──────────────────────────────────────────────────────────────────

const publishers = JSON.parse(readFileSync("publishers.json", "utf8"));
const errors = [];
const entries = [];
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
for (const folder of readdirSync("widgets").sort()) {
    const dir = join("widgets", folder);
    if (!lstatSync(dir).isDirectory()) continue;
    try {
        const { manifest, hash, files, publicKey } = checkWidget(dir, folder, publishers);
        const zipName = `${manifest.id}-${manifest.version}.zip`;
        const bytes = zip(manifest.id, files);
        writeFileSync(join(OUT, zipName), bytes);
        entries.push({
            id: manifest.id,
            name: manifest.name,
            version: manifest.version,
            ...(manifest.description ? { description: manifest.description } : {}),
            ...(manifest.author ? { author: manifest.author } : {}),
            ...(manifest.homepage ? { homepage: manifest.homepage } : {}),
            ...(manifest.icon ? { icon: manifest.icon } : {}),
            permissions: manifest.permissions ?? [],
            hash,
            publisherKey: publicKey,
            zip: `${BASE_URL}/${zipName}`,
            zipSha256: createHash("sha256").update(bytes).digest("hex"),
        });
        console.log(`ok   ${manifest.id} ${manifest.version}`);
    } catch (e) {
        errors.push(`${folder}: ${e instanceof Error ? e.message : String(e)}`);
    }
}
if (errors.length) {
    for (const e of errors) console.error(`FAIL ${e}`);
    process.exit(1);
}
const index = Buffer.from(JSON.stringify({ catalogVersion: 1, generated: new Date().toISOString(), widgets: entries }, null, 2) + "\n");
writeFileSync(join(OUT, "index.json"), index);
const seed = process.env.CATALOG_SIGNING_SEED;
if (seed) {
    const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed, "base64")]), format: "der", type: "pkcs8" });
    writeFileSync(join(OUT, "index.json.sig"), sign(null, index, key).toString("base64") + "\n");
    console.log("signed index.json");
}
console.log(`${entries.length} widget(s) in the catalog`);
