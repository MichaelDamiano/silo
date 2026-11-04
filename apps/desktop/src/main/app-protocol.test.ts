import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { allowedRequest, isAppPage, resolveAppFile } from './app-protocol.js';

const root = path.resolve('/opt/silo/renderer');

describe('app:// protocol', () => {
  it('serves bundled files', () => {
    expect(resolveAppFile(root, 'app://silo/index.html')).toEqual({ file: path.join(root, 'index.html'), type: 'text/html; charset=utf-8' });
    expect(resolveAppFile(root, 'app://silo/')?.file).toBe(path.join(root, 'index.html'));
    expect(resolveAppFile(root, 'app://silo/assets/index-abc.js')?.file).toBe(path.join(root, 'assets/index-abc.js'));
  });

  it('refuses anything outside the renderer folder', () => {
    for (const url of [
      'app://silo/../main/main.js',
      'app://silo/%2e%2e/main/main.js',
      'app://silo/assets/%2e%2e%2f%2e%2e%2fmain/main.js',
      'app://silo/..%5cmain%5cmain.js',
      'app://silo/index.html%00.js',
      'app://silo/%E0%A4%A',
    ]) {
      const hit = resolveAppFile(root, url);
      if (hit) expect(hit.file.startsWith(root + path.sep)).toBe(true);
    }
    expect(resolveAppFile(root, 'app://silo/..%5cmain%5cmain.js')).toBeNull();
    expect(resolveAppFile(root, 'app://silo/index.html%00.js')).toBeNull();
  });

  it('refuses other hosts, schemes and file types', () => {
    expect(resolveAppFile(root, 'app://evil/index.html')).toBeNull();
    expect(resolveAppFile(root, 'app://user@silo/index.html')).toBeNull();
    expect(resolveAppFile(root, 'file:///opt/silo/renderer/index.html')).toBeNull();
    expect(resolveAppFile(root, 'app://silo/assets/index.js.map')).toBeNull();
    expect(resolveAppFile(root, 'app://silo/package')).toBeNull();
  });

  it('trusts only the bundled index page for IPC', () => {
    expect(isAppPage('app://silo/index.html')).toBe(true);
    expect(isAppPage('app://silo/index.html#x')).toBe(true);
    expect(isAppPage('app://silo/other.html')).toBe(false);
    expect(isAppPage('app://silo/index.html?x=1')).toBe(false);
    expect(isAppPage('file:///opt/silo/renderer/index.html')).toBe(false);
    expect(isAppPage('https://silo/index.html')).toBe(false);
    expect(isAppPage(undefined)).toBe(false);
  });

  it('lets the renderer load only its own files', () => {
    expect(allowedRequest('app://silo/assets/a.js', false)).toBe(true);
    expect(allowedRequest('https://example.com/x.png', false)).toBe(false);
    expect(allowedRequest('file:///etc/passwd', false)).toBe(false);
    expect(allowedRequest('app://silo.evil/x', false)).toBe(false);
    expect(allowedRequest('devtools://devtools/x', false)).toBe(false);
    expect(allowedRequest('devtools://devtools/x', true)).toBe(true);
  });
});
