import type { ZipEntry } from "./zip";
// Heuristic signatures of Android packers/protectors (commercial ones are also abused to hide malware). Matched on
// file names (native stubs, encrypted assets), the manifest Application class and stub classes present in the DEX.
// [name, file-name pattern, class-descriptor prefix pattern]
const SIGNATURES: [string, RegExp | null, RegExp | null][] = [
  ["Jiagu (Qihoo 360)", /(?:^|\/)lib(?:jiagu[^/]*|protectClass)\.so$|^assets\/(?:jiagu[^/]*|libjiagu[^/]*)$/i, /^Lcom\/(?:stub\/StubApp|qihoo\/util\/(?:StubApp|QHClassLoader|Configuration))/],
  ["Bangcle/SecNeo", /(?:^|\/)lib(?:secexe|secmain|SecShell|secpreload|DexHelper[^/]*)\.so$|^assets\/(?:secData0\.jar|bangcleplugin\/|bangcle_classes)/i, /^Lcom\/(?:secneo\/apkwrapper|secshell\/|bangcle\/)/],
  ["ijiami", /(?:^|\/)lib(?:exec|execmain|ijiami[^/]*)\.so$|^assets\/(?:ijiami\.(?:dat|ajm)|ijm_lib\/)/i, /^L(?:com\/shell\/(?:SuperApplication|NativeApplication)|s\/h\/e\/l\/l\/)/],
  ["Tencent Legu", /(?:^|\/)lib(?:shell[a-z0-9_-]*|tup|legudb)\.so$|^assets\/(?:0OO00l111l1l|t86|tosversion|libshell[^/]*)$/i, /^Lcom\/(?:tencent\/StubShell|wrapper\/proxyapplication)\//],
  ["Baidu Protect", /(?:^|\/)libbaiduprotect[^/]*\.so$|^assets\/baiduprotect[^/]*$/i, /^Lcom\/baidu\/protect\//],
  ["Alibaba (AliProtector)", /(?:^|\/)lib(?:mobisec[^/]*|demolish|aliprotector[^/]*)\.so$|^assets\/aliprotector[^/]*$/i, /^Lcom\/ali\/mobisecenhance\//],
  ["NetEase Yidun", /(?:^|\/)libnesec\.so$/i, /^Lcom\/netease\/nis\/wrapper\//],
  ["Kiwisec", /(?:^|\/)libkws(?:cmm|cr|linker)\.so$/i, /^Lcom\/kiwisec\//],
  ["Nagapt/Naga", /(?:^|\/)lib(?:ddog|fdog|chaosvmp)\.so$/i, /^Lcom\/(?:nagapt|chaozhuo)\//],
  ["Dingxiang", /(?:^|\/)libx3g\.so$/i, null],
  ["DexProtector", /(?:^|\/)lib(?:dexprotector[^/]*|dpboot)\.so$|^assets\/(?:dp\.[^/]*\.so\.dat|classes\.dex\.dat)$/i, /^Lcom\/(?:dexprotector|licel)\//],
  ["APKProtect", /(?:^|\/)libAPKProtect[^/]*\.so$/i, /^Lcom\/apkprotect\//],
  ["Promon SHIELD", /(?:^|\/)libshield\.so$/i, /^Lno\/promon\//],
  ["AppSealing", /(?:^|\/)libcovault[^/]*\.so$|^assets\/AppSealing\//i, /^Lcom\/inka\/appsealing\//],
  ["LIAPP", /^assets\/LIAPP[^/]*$/i, /^Lcom\/lockincomp\/liapp\//],
  ["NQ Shield", /(?:^|\/)libnqshield\.so$/i, null],
  ["AppGuard", /(?:^|\/)libAppGuard[^/]*\.so$/i, /^Lcom\/inca\/security\//],
  ["Tencent (itsec)", /(?:^|\/)libitsec\.so$/i, null],
  ["Jiagu (jgdtc)", /(?:^|\/)libjgdtc\.so$/i, null],
];
export type PackerScan = {names: Set<string>; evidence: string[]};
export const packerScan = (): PackerScan => ({names: new Set(), evidence: []});
const hit = (s: PackerScan, name: string, evidence: string) => {s.names.add(name); if (s.evidence.length < 8 && !s.evidence.includes(evidence)) s.evidence.push(evidence);};
export function packerFiles(s: PackerScan, entries: ZipEntry[], application: string) {
  for (const e of entries) if (/^(?:lib|assets)\//.test(e.name)) for (const [name, files] of SIGNATURES) if (files?.test(e.name)) hit(s, name, `file ${e.name.slice(0, 100)}`);
  const app = `L${application.replace(/\./g, "/")};`;
  for (const [name, , classes] of SIGNATURES) if (application && classes?.test(app)) hit(s, name, `application ${application.slice(0, 100)}`);
}
// Called per DEX with its class list (stub loaders live in the small outer DEX).
const ANY_CLASS = new RegExp(SIGNATURES.flatMap(([, , re]) => re ? [`(?:${re.source.slice(1)})`] : []).join("|").replace(/^/, "^(?:") + ")");
export function packerClasses(s: PackerScan, classes: {name: string}[]) {
  for (const c of classes) {
    if (!ANY_CLASS.test(c.name)) continue;
    for (const [name, , re] of SIGNATURES) if (re?.test(c.name)) {hit(s, name, `kelas stub ${c.name.slice(1, -1).replace(/\//g, ".").slice(0, 100)}`); break;}
  }
}
