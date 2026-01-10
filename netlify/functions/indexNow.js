import fetch from "node-fetch";
import { XMLParser } from "fast-xml-parser";

export async function handler() {
  const INDEXNOW_KEY = process.env.INDEXNOW_API_KEY;
  const SITEMAP_URL = process.env.SITEMAP_URL;

  if (!INDEXNOW_KEY || !SITEMAP_URL) {
    return {
      statusCode: 500,
      body: "Missing INDEXNOW_API_KEY or SITEMAP_URL environment variables",
    };
  }

  try {
    // 1. Fetch sitemap
    const sitemapRes = await fetch(SITEMAP_URL);
    if (!sitemapRes.ok) {
      throw new Error("Failed to fetch sitemap");
    }

    const sitemapXML = await sitemapRes.text();

    // 2. Parse sitemap XML
    const parser = new XMLParser();
    const parsed = parser.parse(sitemapXML);

    const urls =
      parsed.urlset?.url?.map((u) => u.loc).filter(Boolean) || [];

    if (urls.length === 0) {
      return {
        statusCode: 200,
        body: "No URLs found in sitemap",
      };
    }

    // 3. Split into batches of 10,000
    const batches = [];
    for (let i = 0; i < urls.length; i += 10000) {
      batches.push(urls.slice(i, i + 10000));
    }

    // 4. Submit each batch
    for (const batch of batches) {
      const payload = {
        host: new URL(batch[0]).host,
        key: INDEXNOW_KEY,
        urlList: batch,
      };

      const res = await fetch("https://api.indexnow.org/indexnow", {
        method: "POST",
        headers: {
          "Content-Type": "application/json; charset=utf-8",
        },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`IndexNow error: ${res.status} ${text}`);
      }
    }

    return {
      statusCode: 200,
      body: `IndexNow submitted ${urls.length} URLs successfully`,
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: err.message,
    };
  }
}