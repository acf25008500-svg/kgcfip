import { createSession, sessionCookie } from './_auth';

interface Env {
  LOGINPW?: string;
  JWT_SECRET?: string;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  
  try {
    const { password } = await request.json() as { password: string };

    if (!env.LOGINPW || !env.JWT_SECRET) {
        console.error("FATAL: LOGINPW or JWT_SECRET is not configured in environment variables.");
        return new Response(JSON.stringify({ success: false, message: '错误: 环境变量未配置！' }), { 
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    if (password === env.LOGINPW) {
      const session = await createSession(env.JWT_SECRET);
      return new Response(JSON.stringify({ 
        success: true,
      }), { headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': sessionCookie(session),
        'Cache-Control': 'no-store',
      } });
    } else {
      return new Response(JSON.stringify({ success: false, message: 'Password incorrect' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
  } catch (e) {
    return new Response(JSON.stringify({ success: false, message: 'Invalid request' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
};
