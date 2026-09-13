import { readCookie, verifySession } from './_auth';

interface Env {
    JWT_SECRET: string;
}

/**
 * 这个中间件会拦截所有 /api/* 的请求
 */
export const onRequest: PagesFunction<Env> = async (context) => {
    const { request, env, next } = context;
    const url = new URL(request.url);

    // Public endpoints: login and the bearer-token subscription endpoint.
    if (url.pathname === '/api/login' || url.pathname === '/api/getips') {
        return await next();
    }

    if (!env.JWT_SECRET) {
        console.error("FATAL: JWT_SECRET is not configured in environment variables.");
        return new Response('Internal Server Error: Auth is not configured.', { status: 500 });
    }

    const session = readCookie(request, 'kgcfip_session');
    if (!session || !(await verifySession(session, env.JWT_SECRET))) {
        return new Response('Unauthorized: Invalid or expired session.', { status: 401 });
    }
    return await next();
};
