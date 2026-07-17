import { NextRequest, NextResponse } from "next/server";

/**
 * Optional HTTP Basic gate for Admin.
 *
 * When ADMIN_BASIC_AUTH_USER and ADMIN_BASIC_AUTH_PASSWORD are both set,
 * every request (except /_next and favicon) requires Basic credentials.
 * When unset, Admin remains open (loopback / VPN only — see DEPLOYMENT.md).
 *
 * This is deliberately NOT multi-user RBAC; it is a single shared operator
 * password to stop accidental LAN exposure. SSO remains future work.
 */
export function proxy(request: NextRequest) {
  const user = process.env.ADMIN_BASIC_AUTH_USER?.trim() ?? "";
  const password = process.env.ADMIN_BASIC_AUTH_PASSWORD ?? "";
  if (!user || !password) {
    return NextResponse.next();
  }

  const header = request.headers.get("authorization");
  if (header?.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice("Basic ".length));
      const sep = decoded.indexOf(":");
      const gotUser = sep >= 0 ? decoded.slice(0, sep) : decoded;
      const gotPass = sep >= 0 ? decoded.slice(sep + 1) : "";
      if (gotUser === user && gotPass === password) {
        return NextResponse.next();
      }
    } catch {
      // fall through to 401
    }
  }

  return new NextResponse("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="kcatta admin"',
      "Cache-Control": "no-store",
    },
  });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"],
};
