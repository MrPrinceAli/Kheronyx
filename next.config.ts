import type { NextConfig } from "next";
const config: NextConfig = {
  serverExternalPackages: ["pdfjs-dist", "adm-zip"],
  poweredByHeader: false,
  async headers() {
    return [{ source: "/(.*)", headers: [
      {key: "X-Content-Type-Options", value: "nosniff"},
      {key: "X-Frame-Options", value: "DENY"},
      {key: "Referrer-Policy", value: "strict-origin-when-cross-origin"},
      {key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()"},
      {key: "Content-Security-Policy", value: `default-src 'self'; script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' https://*.supabase.co; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`}
    ]}];
  }
};
export default config;
