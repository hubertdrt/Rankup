require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const axios = require('axios');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// ── Sécurité HTTP headers ──
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: false,
}));

// ── CORS restreint ──
app.use(cors({ origin: ['https://app.rankbase.fr', 'http://localhost:5500', 'http://localhost:3000'] }));
app.use(express.json({ limit: '1mb' }));

// ── Rate limiting ──
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, max: 100,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Trop de requêtes, réessayez dans quelques minutes.' },
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Trop de tentatives de connexion.' } });
const aiLimiter   = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: "Limite d\'analyses IA atteinte, réessayez dans une heure." } });
const apiLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 60, message: { error: 'Trop de requêtes vers les APIs Google.' } });
app.use('/auth/url', authLimiter);
app.use('/auth/callback', authLimiter);
app.use('/auth/check', authLimiter);
app.use('/ai/analyze', aiLimiter);
app.use('/gsc/', apiLimiter);
app.use('/ga4/', apiLimiter);

// ── Supabase client (service_role — full access, bypass RLS) ──
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── OAuth2 Client ──
function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// ── Nettoyage sessions expirées — toutes les heures ──
setInterval(async () => {
  const expiry = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const { error } = await supabase.from('sessions').delete().lt('last_seen', expiry);
  if (error) console.error('Erreur nettoyage sessions:', error.message);
  else console.log('[cleanup] Sessions expirées supprimées');
}, 60 * 60 * 1000);

// ── Helper : récupérer la session depuis Supabase ──
async function getSession(sessionId) {
  if (!sessionId) return null;
  const { data, error } = await supabase
    .from('sessions')
    .select('*')
    .eq('id', sessionId)
    .single();
  if (error || !data) return null;
  await supabase.from('sessions').update({ last_seen: new Date().toISOString() }).eq('id', sessionId);
  return data;
}

// ── Helper : vérifier le plan utilisateur ──
async function getUserPlan(email) {
  const { data } = await supabase.from('users').select('plan').eq('email', email).single();
  return data?.plan || 'free';
}

// ── Helper : récupérer le client OAuth d'une session ──
async function getClientFromSession(sessionId) {
  const sess = await getSession(sessionId);
  if (!sess) return null;
  const oauth2Client = getOAuthClient();
  oauth2Client.setCredentials({
    access_token: sess.access_token,
    refresh_token: sess.refresh_token,
  });
  return oauth2Client;
}

// AUTH — URL Google
app.get('/auth/url', (req, res) => {
  const oauth2Client = getOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/webmasters.readonly',
      'https://www.googleapis.com/auth/analytics.readonly',
      'https://www.googleapis.com/auth/userinfo.email',
    ],
  });
  res.json({ url });
});

// AUTH — Callback Google
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Code manquant');
  try {
    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: userInfo } = await oauth2.userinfo.get();
    const email = userInfo.email;
    const sessionId = crypto.randomBytes(32).toString('hex');
    const { error: sessionError } = await supabase.from('sessions').upsert({
      id: sessionId,
      email,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token || null,
      last_seen: new Date().toISOString(),
    });
    if (sessionError) {
      console.error('Erreur Supabase session:', sessionError.message);
      return res.status(500).send('Erreur sauvegarde session');
    }
    await supabase.from('users').upsert({ email, plan: 'free' }, { onConflict: 'email', ignoreDuplicates: true });
    res.redirect(`https://app.rankbase.fr/?session=${sessionId}&email=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error('Erreur callback OAuth:', err.message);
    res.status(500).send('Erreur authentification : ' + err.message);
  }
});

// AUTH — Check session
app.get('/auth/check', async (req, res) => {
  const sess = await getSession(req.query.session);
  if (!sess) return res.json({ connected: false });
  res.json({ connected: true, email: sess.email });
});

// AUTH — Logout
app.post('/auth/logout', async (req, res) => {
  const { session } = req.body;
  if (session) await supabase.from('sessions').delete().eq('id', session);
  res.json({ ok: true });
});

// USER — Profil + plan
app.get('/user/me', async (req, res) => {
  const sess = await getSession(req.query.session);
  if (!sess) return res.status(401).json({ error: 'Non connecté' });
  const { data, error } = await supabase
    .from('users').select('email, plan').eq('email', sess.email).single();
  if (error || !data) return res.json({ email: sess.email, plan: 'free' });
  res.json({ email: data.email, plan: data.plan });
});

// GSC — Sites
app.get('/gsc/sites', async (req, res) => {
  const client = await getClientFromSession(req.query.session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  try {
    const sc = google.webmasters({ version: 'v3', auth: client });
    const { data } = await sc.sites.list();
    const sites = (data.siteEntry || []).map(s => ({ url: s.siteUrl, permissionLevel: s.permissionLevel }));
    res.json({ sites });
  } catch (err) {
    console.error('Erreur GSC sites:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GSC — Keywords
app.post('/gsc/keywords', async (req, res) => {
  const { session, siteUrl, startDate, endDate, rowLimit = 50, days = 28 } = req.body;
  if (!siteUrl || typeof siteUrl !== 'string') return res.status(400).json({ error: 'siteUrl invalide' });
  const client = await getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  const effectiveDays = days === 1 ? 3 : days === 3 ? 5 : days;
  const end = endDate || new Date().toISOString().split('T')[0];
  const start = startDate || new Date(Date.now() - effectiveDays * 86400000).toISOString().split('T')[0];
  try {
    const sc = google.webmasters({ version: 'v3', auth: client });
    const { data } = await sc.searchanalytics.query({ siteUrl, requestBody: { startDate: start, endDate: end, searchType: 'web', dimensions: ['query'], rowLimit } });
    const { data: totalsData } = await sc.searchanalytics.query({ siteUrl, requestBody: { startDate: start, endDate: end, searchType: 'web', dimensions: [], rowLimit: 1 } });
    const keywords = (data.rows || []).map(row => ({ keyword: row.keys[0], clicks: row.clicks, impressions: row.impressions, ctr: parseFloat((row.ctr * 100).toFixed(1)), position: parseFloat(row.position.toFixed(1)) }));
    const totalsRow = (totalsData.rows || [])[0];
    const totals = totalsRow ? { clicks: totalsRow.clicks, impressions: totalsRow.impressions, ctr: parseFloat((totalsRow.ctr * 100).toFixed(1)), position: parseFloat(totalsRow.position.toFixed(1)) } : null;
    const prevEnd = new Date(Date.now() - effectiveDays * 86400000).toISOString().split('T')[0];
    const prevStart = new Date(Date.now() - effectiveDays * 2 * 86400000).toISOString().split('T')[0];
    let prevMap = {};
    try {
      const { data: prevData } = await sc.searchanalytics.query({ siteUrl, requestBody: { startDate: prevStart, endDate: prevEnd, searchType: 'web', dimensions: ['query'], rowLimit } });
      (prevData.rows || []).forEach(row => { prevMap[row.keys[0]] = parseFloat(row.position.toFixed(1)); });
    } catch(e) {}
    const keywordsWithDelta = keywords.map(k => { const prevPos = prevMap[k.keyword] || null; return { ...k, prevPosition: prevPos, delta: prevPos !== null ? parseFloat((prevPos - k.position).toFixed(1)) : 0 }; });
    res.json({ keywords: keywordsWithDelta, totals, period: { start, end } });
  } catch (err) {
    console.error('Erreur GSC keywords:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GSC — Keyword trend
app.post('/gsc/keyword-trend', async (req, res) => {
  const { session, siteUrl, keyword, days = 30 } = req.body;
  const client = await getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  const end = new Date().toISOString().split('T')[0];
  const start = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];
  try {
    const sc = google.webmasters({ version: 'v3', auth: client });
    const { data } = await sc.searchanalytics.query({ siteUrl, requestBody: { startDate: start, endDate: end, dimensions: ['date', 'query'], rowLimit: 1000, dimensionFilterGroups: [{ filters: [{ dimension: 'query', operator: 'equals', expression: keyword }] }] } });
    const trend = (data.rows || []).map(row => ({ date: row.keys[0], position: parseFloat(row.position.toFixed(1)), clicks: row.clicks, impressions: row.impressions }));
    res.json({ keyword, trend });
  } catch (err) {
    console.error('Erreur GSC trend:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GSC — Opportunities
app.post('/gsc/opportunities', async (req, res) => {
  const { session, siteUrl, days = 28 } = req.body;
  const client = await getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  const end = new Date().toISOString().split('T')[0];
  const start = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];
  try {
    const sc = google.webmasters({ version: 'v3', auth: client });
    const { data } = await sc.searchanalytics.query({ siteUrl, requestBody: { startDate: start, endDate: end, searchType: 'web', dimensions: ['query', 'page'], rowLimit: 200 } });
    const opportunities = (data.rows || []).filter(row => row.position >= 8 && row.position <= 20).map(row => ({ keyword: row.keys[0], page: row.keys[1], position: parseFloat(row.position.toFixed(1)), clicks: row.clicks, impressions: row.impressions, ctr: parseFloat((row.ctr * 100).toFixed(1)), potential: Math.round(((20 - row.position) / 12) * 8) })).sort((a, b) => b.impressions - a.impressions);
    res.json({ opportunities });
  } catch (err) {
    console.error('Erreur GSC opportunities:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GA4 — Properties
app.get('/ga4/properties', async (req, res) => {
  const client = await getClientFromSession(req.query.session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  try {
    const analyticsAdmin = google.analyticsadmin({ version: 'v1beta', auth: client });
    const { data: accountsData } = await analyticsAdmin.accounts.list();
    const accounts = accountsData.accounts || [];
    if (accounts.length === 0) return res.json({ properties: [] });
    const allProperties = [];
    for (const account of accounts) {
      try {
        const accountId = account.name.replace('accounts/', '');
        const { data } = await analyticsAdmin.properties.list({ filter: `parent:accounts/${accountId}` });
        (data.properties || []).forEach(p => { allProperties.push({ id: p.name.replace('properties/', ''), name: p.displayName, url: p.websiteUri || '', account: account.displayName }); });
      } catch(e) { console.error('Erreur propriétés compte', account.name, e.message); }
    }
    res.json({ properties: allProperties });
  } catch (err) {
    console.error('Erreur GA4 properties:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GA4 — Behavior
app.post('/ga4/behavior', async (req, res) => {
  const { session, propertyId, days = 28 } = req.body;
  const client = await getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });
    const { data } = await analyticsData.properties.runReport({ property: `properties/${propertyId}`, requestBody: { dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }], dimensions: [{ name: 'pagePath' }, { name: 'sessionDefaultChannelGroup' }], metrics: [{ name: 'sessions' }, { name: 'engagedSessions' }, { name: 'averageSessionDuration' }, { name: 'screenPageViewsPerSession' }], dimensionFilter: { filter: { fieldName: 'sessionDefaultChannelGroup', stringFilter: { matchType: 'CONTAINS', value: 'Organic' } } }, orderBys: [{ metric: { metricName: 'sessions' }, desc: true }], limit: 100 } });
    const pageMap = {};
    (data.rows || []).forEach(row => {
      const page = row.dimensionValues[0].value;
      const sessions = parseInt(row.metricValues[0].value) || 0;
      const engagedSessions = parseInt(row.metricValues[1].value) || 0;
      const avgDuration = parseFloat(row.metricValues[2].value) || 0;
      const pagesPerSession = parseFloat(row.metricValues[3].value) || 0;
      const bounceRate = sessions > 0 ? parseFloat(((1 - engagedSessions / sessions) * 100).toFixed(1)) : 0;
      if (!pageMap[page] || sessions > pageMap[page].sessions) pageMap[page] = { page, sessions, bounceRate, avgDuration, pagesPerSession };
    });
    res.json({ pages: Object.values(pageMap).sort((a, b) => b.sessions - a.sessions).slice(0, 50) });
  } catch (err) {
    console.error('Erreur GA4 behavior:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// AI — Analyze (réservé aux comptes premium)
app.post('/ai/analyze', async (req, res) => {
  const { session, gscData, ga4Data, siteUrl } = req.body;
  const sess = await getSession(session);
  if (!sess) return res.status(401).json({ error: 'Non connecté' });
  const plan = await getUserPlan(sess.email);
  if (plan !== 'premium') return res.status(403).json({ error: 'Fonctionnalité réservée au plan Premium.' });
  const prompt = `Tu es un expert SEO. Analyse ces données et fournis un rapport concis en français.\n\nSite : ${siteUrl}\n\nDonnées Search Console :\n- Mots-clés en progression : ${JSON.stringify(gscData?.gainers?.slice(0,5) || [])}\n- Mots-clés en recul : ${JSON.stringify(gscData?.losers?.slice(0,5) || [])}\n- CTR faibles : ${JSON.stringify(gscData?.lowCtr?.slice(0,5) || [])}\n- Opportunités (pos 8-20) : ${JSON.stringify(gscData?.opportunities?.slice(0,5) || [])}\n\nDonnées Analytics (trafic organique) :\n- Pages fort rebond (> 70%) : ${JSON.stringify(ga4Data?.highBounce?.slice(0,5) || [])}\n- Meilleures pages (rebond < 40%) : ${JSON.stringify(ga4Data?.bestPages?.slice(0,3) || [])}\n\nRéponds avec 4 sections séparées par ### :\n### Gains — Ce qui progresse et pourquoi\n### Problèmes — Ce qui recule ou déçoit\n### Opportunités — Les 3 mots-clés à prioriser\n### Actions — 3 actions concrètes à faire maintenant\n\nSois direct, concis, actionnable.`;
  try {
    const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', { model: process.env.OPENROUTER_MODEL || 'openai/gpt-4o-mini', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] }, { headers: { 'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://app.rankbase.fr', 'X-Title': 'Rankup SEO' }, timeout: 30000 });
    res.json({ content: response.data.choices[0].message.content });
  } catch (err) {
    console.error('Erreur OpenRouter:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GA4 — Geo + Devices
app.post('/ga4/geo-devices', async (req, res) => {
  const { session, propertyId, days = 28 } = req.body;
  const client = await getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });
    const [{ data: countryData }, { data: deviceData }] = await Promise.all([
      analyticsData.properties.runReport({ property: `properties/${propertyId}`, requestBody: { dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }], dimensions: [{ name: 'country' }], metrics: [{ name: 'sessions' }], dimensionFilter: { filter: { fieldName: 'sessionDefaultChannelGroup', stringFilter: { matchType: 'CONTAINS', value: 'Organic' } } }, orderBys: [{ metric: { metricName: 'sessions' }, desc: true }], limit: 8 } }),
      analyticsData.properties.runReport({ property: `properties/${propertyId}`, requestBody: { dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }], dimensions: [{ name: 'deviceCategory' }], metrics: [{ name: 'sessions' }], dimensionFilter: { filter: { fieldName: 'sessionDefaultChannelGroup', stringFilter: { matchType: 'CONTAINS', value: 'Organic' } } }, orderBys: [{ metric: { metricName: 'sessions' }, desc: true }], limit: 5 } }),
    ]);
    res.json({ countries: (countryData.rows || []).map(r => ({ country: r.dimensionValues[0].value, sessions: parseInt(r.metricValues[0].value) })), devices: (deviceData.rows || []).map(r => ({ device: r.dimensionValues[0].value, sessions: parseInt(r.metricValues[0].value) })) });
  } catch (err) {
    console.error('Erreur GA4 geo-devices:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GA4 — Realtime
app.post('/ga4/realtime', async (req, res) => {
  const { session, propertyId } = req.body;
  const client = await getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });
  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });
    const [activeUsers, pageViews, countries] = await Promise.all([
      analyticsData.properties.runRealtimeReport({ property: `properties/${propertyId}`, requestBody: { metrics: [{ name: 'activeUsers' }] } }),
      analyticsData.properties.runRealtimeReport({ property: `properties/${propertyId}`, requestBody: { dimensions: [{ name: 'unifiedPagePathScreen' }], metrics: [{ name: 'activeUsers' }], orderBys: [{ metric: { metricName: 'activeUsers' }, desc: true }], limit: 10 } }),
      analyticsData.properties.runRealtimeReport({ property: `properties/${propertyId}`, requestBody: { dimensions: [{ name: 'country' }], metrics: [{ name: 'activeUsers' }], orderBys: [{ metric: { metricName: 'activeUsers' }, desc: true }], limit: 5 } }),
    ]);
    res.json({ totalActive: parseInt((activeUsers.data.rows || [{ metricValues: [{ value: '0' }] }])[0]?.metricValues[0]?.value || 0), pages: (pageViews.data.rows || []).map(r => ({ page: r.dimensionValues[0].value, users: parseInt(r.metricValues[0].value) })), countries: (countries.data.rows || []).map(r => ({ countryId: r.dimensionValues[0].value, users: parseInt(r.metricValues[0].value) })), timestamp: Date.now() });
  } catch (err) {
    console.error('Erreur GA4 realtime:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Sanity check
app.get('/', (req, res) => res.json({ status: 'Rankup backend OK', version: '2.1.0-secure' }));

// ── 404 ──
app.use((req, res) => res.status(404).json({ error: 'Route introuvable' }));

// ── Error handler global ──
app.use((err, req, res, next) => {
  console.error('Erreur non gérée:', err.message);
  res.status(500).json({ error: 'Erreur serveur interne' });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`\n🚀 Rankup backend démarré sur http://localhost:${PORT}`);
  console.log(`   Supabase : ${process.env.SUPABASE_URL}`);
  console.log(`   Auth URL : http://localhost:${PORT}/auth/url\n`);
});
