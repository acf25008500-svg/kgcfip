const encoder = new TextEncoder();
const SESSION_DURATION_SECONDS = 8 * 60 * 60;

function base64UrlEncode(value: Uint8Array | string): string {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function signingKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function createSession(secret: string): Promise<string> {
  const payload = base64UrlEncode(JSON.stringify({ exp: Date.now() + SESSION_DURATION_SECONDS * 1000 }));
  const signature = await crypto.subtle.sign('HMAC', await signingKey(secret), encoder.encode(payload));
  return `${payload}.${base64UrlEncode(new Uint8Array(signature))}`;
}

export async function verifySession(token: string, secret: string): Promise<boolean> {
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;
  try {
    const signatureBytes = base64UrlDecode(signature);
    const signatureBuffer = signatureBytes.buffer.slice(
      signatureBytes.byteOffset,
      signatureBytes.byteOffset + signatureBytes.byteLength,
    ) as ArrayBuffer;
    const validSignature = await crypto.subtle.verify('HMAC', await signingKey(secret), signatureBuffer, encoder.encode(payload));
    if (!validSignature) return false;
    const data = JSON.parse(new TextDecoder().decode(base64UrlDecode(payload))) as { exp?: number };
    return typeof data.exp === 'number' && data.exp > Date.now();
  } catch {
    return false;
  }
}

export function sessionCookie(token: string): string {
  return `kgcfip_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DURATION_SECONDS}`;
}

export function readCookie(request: Request, name: string): string | null {
  const cookies = request.headers.get('Cookie') ?? '';
  const match = cookies.split(';').map((item) => item.trim()).find((item) => item.startsWith(`${name}=`));
  return match ? match.slice(name.length + 1) : null;
}
