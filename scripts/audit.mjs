import fs from "node:fs/promises";
import path from "node:path";

const site = (process.env.SITE_URL || "https://musikilugati.com").replace(/\/$/, "");
const reportDir = path.resolve("reports");
const origin = new URL(site).origin;

await fs.mkdir(reportDir, { recursive: true });

async function fetchText(url, options = {}) {
  const response = await fetch(url, {
    redirect: "follow",
    ...options,
    headers: { "user-agent": "musikilugati-audit/1.0", ...options.headers },
  });
  const text = await response.text();
  return { response, text };
}

function attrs(html, name) {
  const pattern = new RegExp(`<${name}\\b[^>]*>`, "gi");
  return [...html.matchAll(pattern)].map((match) => match[0]);
}

function extractValues(html, attribute) {
  const pattern = new RegExp(`\\b${attribute}\\s*=\\s*(["'])(.*?)\\1`, "gi");
  return [...html.matchAll(pattern)].map((match) => match[2]);
}

const findings = [];
const checks = {};
let home;

try {
  home = await fetchText(site);
  checks.httpStatus = home.response.status;
  checks.finalUrl = home.response.url;
  checks.headers = Object.fromEntries([...home.response.headers.entries()]);

  const head = home.text.match(/<head\b[^>]*>([\s\S]*?)<\/head>/i)?.[1] || "";
  const title = head.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || "";
  const metaDescription = [...head.matchAll(/<meta\b[^>]*>/gi)]
    .map((match) => match[0])
    .find((tag) => /name\s*=\s*["']description["']/i.test(tag));
  const canonical = [...head.matchAll(/<link\b[^>]*>/gi)]
    .map((match) => match[0])
    .find((tag) => /rel\s*=\s*["']canonical["']/i.test(tag));
  const h1Count = attrs(home.text, "h1").length;

  checks.seo = {
    title,
    titleLength: title.length,
    metaDescription: Boolean(metaDescription),
    canonical: canonical ? extractValues(canonical, "href")[0] || null : null,
    h1Count,
  };

  if (!title) findings.push({ severity: "high", category: "SEO", message: "Sayfa basligi (title) bulunamadi." });
  if (title && (title.length < 30 || title.length > 60)) {
    findings.push({ severity: "medium", category: "SEO", message: `Title uzunlugu ${title.length} karakter; uygun aralik genellikle 30-60 karakterdir.` });
  }
  if (!metaDescription) findings.push({ severity: "medium", category: "SEO", message: "Meta description bulunamadi." });
  if (!canonical) findings.push({ severity: "medium", category: "SEO", message: "Canonical etiketi bulunamadi." });
  if (h1Count !== 1) findings.push({ severity: "medium", category: "SEO", message: `Ana sayfada ${h1Count} adet h1 etiketi bulundu.` });

  const headers = home.response.headers;
  const securityHeaders = {
    "strict-transport-security": headers.get("strict-transport-security"),
    "content-security-policy": headers.get("content-security-policy"),
    "x-frame-options": headers.get("x-frame-options"),
    "x-content-type-options": headers.get("x-content-type-options"),
    "referrer-policy": headers.get("referrer-policy"),
    "permissions-policy": headers.get("permissions-policy"),
  };
  checks.securityHeaders = securityHeaders;

  for (const [header, value] of Object.entries(securityHeaders)) {
    if (!value) {
      findings.push({
        severity: header === "strict-transport-security" || header === "content-security-policy" ? "high" : "medium",
        category: "Security",
        message: `${header} basligi eksik.`,
      });
    }
  }

  const setCookies = [...home.response.headers.entries()]
    .filter(([name]) => name === "set-cookie")
    .map(([, value]) => value);
  checks.cookies = setCookies.map((cookie) => ({
    secure: /;\s*secure(?:;|$)/i.test(cookie),
    httpOnly: /;\s*httponly(?:;|$)/i.test(cookie),
    sameSite: /;\s*samesite=(lax|strict|none)/i.exec(cookie)?.[1] || null,
  }));
  for (const cookie of checks.cookies) {
    if (!cookie.secure || !cookie.httpOnly) {
      findings.push({ severity: "high", category: "Security", message: "Bir oturum/istatistik cerezinde Secure veya HttpOnly bayragi eksik." });
    }
  }

  const mixedContent = [...home.text.matchAll(/(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi)].map((match) => match[0]);
  checks.mixedContentCount = mixedContent.length;
  if (mixedContent.length) {
    findings.push({ severity: "high", category: "Security", message: `Sayfada ${mixedContent.length} adet HTTP karisik icerik baglantisi bulundu.` });
  }

  const links = extractValues(home.text, "href");
  const internalLinks = new Set();
  for (const href of links) {
    if (!href) continue;
    try {
      const absolute = new URL(href, home.response.url);
      if (absolute.origin === origin && !absolute.pathname.match(/\.(?:jpg|jpeg|png|gif|svg|pdf|zip)$/i)) {
        internalLinks.add(absolute.href);
      }
    } catch {}
  }

  const queue = [home.response.url];
  const visited = new Set();
  const broken = [];
  const htmlPages = new Map();

  while (queue.length && visited.size < 25) {
    const url = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);
    try {
      const { response, text } = await fetchText(url);
      htmlPages.set(url, text);
      if (!response.ok) broken.push({ url, status: response.status });
      if (response.ok && response.headers.get("content-type")?.includes("text/html")) {
        for (const href of extractValues(text, "href")) {
          if (!href) continue;
          try {
            const absolute = new URL(href, url);
            if (absolute.origin === origin && !visited.has(absolute.href) && absolute.pathname !== "/wp-json" && !/\.(?:jpg|jpeg|png|gif|svg|pdf|zip)$/i.test(absolute.pathname)) {
              queue.push(absolute.href);
            }
          } catch {}
        }
      }
    } catch (error) {
      broken.push({ url, status: error.message });
    }
  }

  checks.crawl = { visitedPages: visited.size, brokenLinks: broken };
  if (broken.length) {
    findings.push({ severity: "high", category: "Reliability", message: `Taramada ${broken.length} bozuk veya erisilemeyen ayni alan adi baglantisi bulundu.` });
  }

  const robots = await fetchText(new URL("/robots.txt", origin).href).catch(() => null);
  const sitemap = await fetchText(new URL("/sitemap.xml", origin).href).catch(() => null);
  checks.robots = { status: robots?.response.status || null };
  checks.sitemap = { status: sitemap?.response.status || null };
  if (robots?.response.status !== 200) findings.push({ severity: "low", category: "SEO", message: "robots.txt bulunamadi veya erisilemiyor." });
  if (sitemap?.response.status !== 200) findings.push({ severity: "medium", category: "SEO", message: "sitemap.xml bulunamadi veya erisilemiyor." });

  const images = attrs(home.text, "img");
  const missingAlt = images.filter((tag) => !/\balt\s*=/.test(tag)).length;
  checks.accessibility = { images: images.length, missingAlt };
  if (missingAlt) findings.push({ severity: "medium", category: "Accessibility", message: `Ana sayfada ${missingAlt} resmin alt ozelligi yok.` });

  if (!home.response.url.startsWith("https://")) {
    findings.push({ severity: "high", category: "Security", message: "Son URL HTTPS kullanmiyor." });
  }
} catch (error) {
  findings.push({ severity: "critical", category: "Availability", message: `Ana sayfa denetlenemedi: ${error.message}` });
  checks.httpStatus = null;
}

const lighthousePath = path.join(reportDir, "lighthouse.json");
try {
  await fs.access(lighthousePath);
  const lighthouse = JSON.parse(await fs.readFile(lighthousePath, "utf8"));
  checks.lighthouse = Object.fromEntries(
    ["performance", "accessibility", "seo", "best-practices"].map((category) => [
      category,
      lighthouse.categories?.[category]?.score == null ? null : Math.round(lighthouse.categories[category].score * 100),
    ]),
  );
} catch {
  checks.lighthouse = null;
}

const summary = {
  generatedAt: new Date().toISOString(),
  site,
  findings,
  checks,
};

await fs.writeFile(path.join(reportDir, "audit.json"), JSON.stringify(summary, null, 2));

const severityCounts = findings.reduce((counts, finding) => {
  counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  return counts;
}, {});

const findingRows = findings.length
  ? findings.map((finding) => `| ${finding.severity} | ${finding.category} | ${finding.message} |`).join("\n")
  : "| - | - | Bulgu bulunmadi. |";

const lighthouseRows = checks.lighthouse
  ? Object.entries(checks.lighthouse).map(([name, score]) => `| ${name} | ${score ?? "N/A"} |`).join("\n")
  : "| Lighthouse | Calistirilmadi |";

const markdown = `# musikilugati.com Denetim Raporu

- Tarih: ${summary.generatedAt}
- HTTP durumu: ${checks.httpStatus ?? "Erisilemedi"}
- Son URL: ${checks.finalUrl || site}
- Taranan sayfa: ${checks.crawl?.visitedPages ?? 0}

## Bulgular

| Oncelik | Kategori | Aciklama |
|---|---|---|
${findingRows}

Oncelik ozeti: ${Object.entries(severityCounts).map(([key, value]) => `${key}=${value}`).join(", ") || "bulgu yok"}

## Lighthouse

| Kategori | Puan |
|---|---:|
${lighthouseRows}

## SEO

- Title: ${checks.seo?.title || "Bulunamadi"}
- Title uzunlugu: ${checks.seo?.titleLength ?? "N/A"}
- Meta description: ${checks.seo?.metaDescription ? "Var" : "Yok"}
- Canonical: ${checks.seo?.canonical || "Yok"}
- H1 sayisi: ${checks.seo?.h1Count ?? "N/A"}
- robots.txt HTTP durumu: ${checks.robots?.status ?? "N/A"}
- sitemap.xml HTTP durumu: ${checks.sitemap?.status ?? "N/A"}

## Erisilebilirlik

- Resim sayisi: ${checks.accessibility?.images ?? "N/A"}
- Alt ozelligi olmayan resim: ${checks.accessibility?.missingAlt ?? "N/A"}

Detayli makineler tarafindan okunabilir JSON cikti: \`reports/audit.json\`.
`;

await fs.writeFile(path.join(reportDir, "summary.md"), markdown);
await fs.writeFile("AUDIT_SUMMARY.md", markdown);

console.log(markdown);
