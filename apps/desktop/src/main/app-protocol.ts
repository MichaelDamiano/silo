import path from 'node:path';

/**
 * The renderer is served from app://silo/ instead of file://. A file:// page can
 * read any file the user can, and every file:// page shares one origin; app://silo
 * only ever serves the files we bundled.
 */
export const APP_SCHEME = 'app';
export const APP_HOST = 'silo';
export const APP_ORIGIN = `${APP_SCHEME}://${APP_HOST}`;
export const APP_INDEX = `${APP_ORIGIN}/index.html`;

/** The same policy as the meta tag in index.html, sent as a header so it applies before any markup is parsed. */
export const RENDERER_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.json': 'application/json',
};

/**
 * Maps an app://silo/ URL to a file inside the renderer folder, or returns null
 * for anything else: another host, a path that climbs out of the folder, or a
 * file type we don't ship.
 */
export function resolveAppFile(rendererDir: string, rawUrl: string): { file: string; type: string } | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.protocol !== `${APP_SCHEME}:` || url.host !== APP_HOST || url.username || url.password || url.port) return null;
  let pathname: string;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return null;
  }
  if (pathname.includes('\0') || pathname.includes('\\')) return null;
  const root = path.resolve(rendererDir);
  const file = path.resolve(root, '.' + path.posix.normalize(pathname === '/' ? '/index.html' : pathname));
  if (file !== root && !file.startsWith(root + path.sep)) return null;
  const type = TYPES[path.extname(file).toLowerCase()];
  if (!type) return null;
  return { file, type };
}

/** True only for our own bundled page, the one frame allowed to call into the main process. */
export function isAppPage(rawUrl: string | undefined): boolean {
  if (!rawUrl) return false;
  try {
    const url = new URL(rawUrl);
    return url.protocol === `${APP_SCHEME}:` && url.host === APP_HOST && url.pathname === '/index.html' && !url.search;
  } catch {
    return false;
  }
}

/** Requests the renderer's session may make: our own files, plus DevTools in development. */
export function allowedRequest(rawUrl: string, dev: boolean): boolean {
  if (rawUrl.startsWith(`${APP_ORIGIN}/`)) return true;
  return dev && rawUrl.startsWith('devtools://');
}
