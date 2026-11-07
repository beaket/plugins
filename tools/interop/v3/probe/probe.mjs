import { webcrypto as crypto } from "node:crypto";
import { readFileSync } from "node:fs";
const { subtle } = crypto;
const KEM = { name: "ML-KEM-768" };
const h = (s) => new Uint8Array(Buffer.from(s, "hex"));
const hx = (b) => Buffer.from(b).toString("hex");
const mode = process.argv[2];
if (mode === "gen") {
  const k = await subtle.generateKey(KEM, true, ["encapsulateBits", "decapsulateBits"]);
  console.log(hx(new Uint8Array(await subtle.exportKey("raw-seed", k.privateKey))) + " " + hx(new Uint8Array(await subtle.exportKey("raw-public", k.publicKey))));
  process.exit(0);
}
const v = JSON.parse(readFileSync(process.argv[3], "utf8"));
// ML-KEM: Go seed into WebCrypto
const priv = await subtle.importKey("raw-seed", h(v.seed), KEM, true, ["decapsulateBits"]);
let pubOk = "n/a";
try { const pk = await subtle.getPublicKey(priv, ["encapsulateBits"]); pubOk = hx(new Uint8Array(await subtle.exportKey("raw-public", pk))) === v.ek; } catch (e) { pubOk = "getPublicKey: " + e.message; }
console.log("node mlkem: Go seed accepted; derived raw-public == Go ek:", pubOk);
const good = hx(new Uint8Array(await subtle.decapsulateBits(KEM, priv, h(v.ct))));
console.log("node mlkem: decap of Go ct == Go ss:", good === v.ssGood);
try {
  const bad = hx(new Uint8Array(await subtle.decapsulateBits(KEM, priv, h(v.ctBad))));
  console.log("node mlkem: flipped ct -> no error, implicit-rejection key == Go's:", bad === v.ssBad, "; differs from real:", bad !== v.ssGood);
} catch (e) { console.log("node mlkem: flipped ct threw", e.message); }
for (const n of [32, 63, 65]) {
  try { await subtle.importKey("raw-seed", new Uint8Array(n), KEM, false, ["decapsulateBits"]); console.log(`node mlkem: ${n}-byte seed accepted`); }
  catch (e) { console.log(`node mlkem: ${n}-byte seed refused: ${e.name}`); }
}
try { await subtle.importKey("raw-public", new Uint8Array(1183), KEM, false, ["encapsulateBits"]); console.log("node mlkem: 1183-byte ek accepted"); }
catch (e) { console.log("node mlkem: 1183-byte ek refused:", e.name); }
// X25519 low order
const x = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
for (const [name, p] of Object.entries({ zero: "00".repeat(32), one: "01" + "00".repeat(31), ord8: "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "p-1": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" })) {
  try {
    const pub = await subtle.importKey("raw", h(p), { name: "X25519" }, false, []);
    const s = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, x.privateKey, 256));
    console.log(`node x25519 ${name}: deriveBits returned ${hx(s)}`);
  } catch (e) { console.log(`node x25519 ${name}: refused (${e.name}: ${e.message})`); }
}
// Ed25519
const ver = async (pub, sig) => {
  try { const k = await subtle.importKey("raw", h(pub), { name: "Ed25519" }, false, ["verify"]); return await subtle.verify({ name: "Ed25519" }, k, h(sig), h(v.msg)); }
  catch (e) { return "threw " + e.name; }
};
console.log("node ed25519: valid sig verifies:", await ver(v.edPub, v.sig), "; S+L sig verifies:", await ver(v.edPub, v.sigMal));
console.log("node ed25519: identity public key, sig (R=identity,S=0) verifies:", await ver(v.identPub, v.weakSig));
