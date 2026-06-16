import type { NextConfig } from "next";

// Security response headers applied to every route. The CSP is intentionally
// scoped to `frame-ancestors 'none'` (anti-clickjacking — the key gap, given the
// one-click scan/target dispatch actions) so it does not restrict Next's inline
// runtime scripts/styles; a full content CSP with nonces is a follow-up.
const securityHeaders = [
  { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
