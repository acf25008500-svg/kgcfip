interface Env {
  APITOKEN?: string;
}

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  if (!env.APITOKEN) {
    return Response.json({ message: 'Subscription token is not configured.' }, { status: 500 });
  }

  const url = new URL('/api/getips', request.url);
  url.searchParams.set('token', env.APITOKEN);
  return Response.json({ url: url.toString() }, { headers: { 'Cache-Control': 'no-store' } });
};
