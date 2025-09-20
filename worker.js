export default {
  async fetch(request, env, ctx) {
    const cacheUrl = new URL(request.url);
    const cache = caches.default;

    // Check Cloudflare edge cache
    let response = await cache.match(cacheUrl);

    if (!response) {
      const fileUrl =
        "https://raw.githubusercontent.com/mieweb/pown.sh/refs/heads/main/pown.sh";
      const apiUrl =
        "https://api.github.com/repos/mieweb/pown.sh/commits/main";

      // Fetch script
      const originRes = await fetch(fileUrl, {
        headers: { "User-Agent": "pown.sh via Cloudflare Worker" },
      });
      if (!originRes.ok) {
        return new Response(
          `Error fetching script: ${originRes.status}`,
          { status: 502 }
        );
      }
      let script = await originRes.text();

      // Fetch commit metadata
      let commitSha = "unknown";
      try {
        const apiRes = await fetch(apiUrl, {
          headers: { "User-Agent": "pown.sh via Cloudflare Worker" },
        });
        if (apiRes.ok) {
          const data = await apiRes.json();
          commitSha = data.sha.slice(0, 12); // short hash
        }
      } catch (e) {
        // ignore API errors
      }

      // Build footer
      const fetchedAt = new Date().toISOString();
      script += `\n\n# ---\n`;
      script += `# Source: ${fileUrl}\n`;
      script += `# Last updated: ${fetchedAt}\n`;
      script += `# Commit: ${commitSha}\n`;
      script += `# Repo: https://github.com/mieweb/pown.sh\n`;

      response = new Response(script, {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "public, max-age=10", // short
        },
      });

      // Store in Cloudflare cache
      ctx.waitUntil(cache.put(cacheUrl, response.clone()));
    }

    return response;
  },
};