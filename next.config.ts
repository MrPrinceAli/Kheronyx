import type { NextConfig } from "next";
const config: NextConfig = {
  serverExternalPackages: ["pdfjs-dist", "adm-zip", "@napi-rs/canvas"],
  // pdf.js needs @napi-rs/canvas (DOMMatrix/Path2D) under Node and loads it with a dynamic require that
  // file tracing cannot see; without it the pdf.js import throws "DOMMatrix is not defined" on Vercel.
  outputFileTracingIncludes: {"/api/analyze": ["./node_modules/pdfjs-dist/legacy/build/pdf.worker.mjs", "./node_modules/@napi-rs/canvas/**", "./node_modules/@napi-rs/canvas-linux-*/**"]},
  poweredByHeader: false,
  async headers() {
    return [{ source: "/(.*)", headers: [
      {key: "X-Content-Type-Options", value: "nosniff"},
      {key: "X-Frame-Options", value: "DENY"},
      {key: "Referrer-Policy", value: "strict-origin-when-cross-origin"},
      {key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()"},
      {key: "Content-Security-Policy", value: `default-src 'self'; script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' https://*.supabase.co https://vercel.com/api/blob/; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`}
    ]}];
  }
};
export default config;
