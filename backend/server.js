// ════════════════════════════════════════════════════════════════
// RANKUP BACKEND — server.js
// Version sécurisée
// ════════════════════════════════════════════════════════════════
//
// SÉCURITÉ — Ce qui a changé par rapport à la version initiale :
//
// 1. CORS restreint à app.rankbase.fr uniquement
//    → Avant : cors({ origin: '*' }) acceptait n'importe quel site
//    → Maintenant : seul le frontend officiel peut appeler l'API
//
// 2. SessionId aléatoire et non prévisible
//    → Avant : base64(email) — devinable si on connaît l'email
//    → Maintenant : crypto.randomBytes(32) — 256 bits d'entropie
//
// 3. Rate limiting sur toutes les routes
//    → Limite les appels à 100/15min par IP pour les routes normales
//    → Limite plus stricte sur /auth (20/15min) pour bloquer le brute force
//    → Limite très stricte sur /ai/analyze (10/heure) pour protéger la clé OpenRouter
//
// 4. Route /ai/analyze protégée par session
//    → Avant : accessible sans être connecté → consommation gratuite de ta clé
//    → Maintenant : session valide obligatoire
//
// 5. Erreurs internes masquées
//    → Avant : err.message renvoyé au client (révèle la stack interne)
//    → Maintenant : message générique au client, vrai message dans les logs serveur
//
// 6. Validation basique des inputs
//    → Vérification que session, siteUrl, propertyId sont des strings non vides
//    → Évite les crashs sur des inputs malformés
//
// 7. Helmet — en-têtes de sécurité HTTP
//    → Ajoute automatiquement X-Frame-Options, X-Content-Type-Options,
//      Content-Security-Policy, etc.
//    → Protège contre clickjacking, MIME sniffing, XSS basique
//
// ════════════════════════════════════════════════════════════════

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto   = require('crypto');   // module natif Node — pas besoin d'installer
const { google } = require('googleapis');
const axios    = require('axios');

const app = express();

// ── Helmet — en-têtes de sécurité HTTP ──────────────────────────
// helmet() active une dizaine de middlewares en une ligne.
// Ils ajoutent des headers qui indiquent au navigateur de ne pas
// exécuter le contenu dans une iframe, de ne pas deviner le MIME type, etc.
app.use(helmet());

// ── CORS — restreindre l'accès à notre seul frontend ────────────
// Sans ça, n'importe quel site web peut appeler notre API depuis
// le navigateur d'un utilisateur connecté et voler ses données.
const ALLOWED_ORIGINS = [
  'https://app.rankbase.fr',
  'http://localhost:5500',   // dev local VS Code Live Server
  'http://localhost:3000',   // dev local autre
];
app.use(cors({
  origin: (origin, callback) => {
    // Autorise les requêtes sans origin (Postman, curl, server-to-server)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS bloqué pour l'origine : ${origin}`));
  },
  credentials: true,
}));

app.use(express.json({ limit: '50kb' }));  // limite la taille du body pour éviter les attaques par payload géant

// ── Rate limiting ────────────────────────────────────────────────
// Sans rate limiting, un bot peut appeler /ai/analyze en boucle
// et épuiser ta clé OpenRouter en quelques secondes.

// Limite générale : 100 requêtes par IP toutes les 15 minutes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requêtes. Réessayez dans quelques minutes.' },
});

// Limite stricte pour l'auth : 20 tentatives par IP toutes les 15 minutes
// Protège contre le brute force du callback OAuth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Trop de tentatives de connexion. Réessayez dans quelques minutes.' },
});

// Limite très stricte pour l'IA : 10 analyses par heure par IP
// Chaque appel coûte de l'argent — on ne veut pas se faire abuser
const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Limite d\'analyses IA atteinte. Réessayez dans une heure.' },
});

app.use(generalLimiter);        // appliqué à toutes les routes par défaut

// ── Sessions en mémoire ──────────────────────────────────────────
// Toujours en mémoire pour l'instant — Supabase/Redis viendra après.
// La différence avec avant : la clé n'est plus devinable (voir AUTH ci-dessous).
const sessions = {};

// ── Nettoyage des sessions expirées ─────────────────────────────
// Les tokens Google expirent après 1h. On nettoie les sessions toutes
// les heures pour éviter que la mémoire ne grossisse indéfiniment.
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [id, sess] of Object.entries(sessions)) {
    // Si le token a expiré (expiry_date fourni par Google OAuth)
    if (sess.tokens?.expiry_date && sess.tokens.expiry_date < now) {
      delete sessions[id];
      cleaned++;
    }
  }
  if (cleaned > 0) console.log(`[Session cleanup] ${cleaned} session(s) expirée(s) supprimée(s)`);
}, 60 * 60 * 1000);

// ── Helper OAuth ─────────────────────────────────────────────────
function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// ── Helper : récupérer le client OAuth d'une session ─────────────
// Retourne null si la session est invalide ou expirée.
function getClientFromSession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') return null;
  const sess = sessions[sessionId];
  if (!sess) return null;
  const oauth2Client = getOAuthClient();
  oauth2Client.setCredentials(sess.tokens);
  return oauth2Client;
}

// ── Helper : validation des inputs ──────────────────────────────
// Vérifie qu'une valeur est une string non vide.
// Évite les crashs sur des inputs null/undefined/objet malformé.
function isValidString(val, maxLen = 500) {
  return typeof val === 'string' && val.trim().length > 0 && val.length <= maxLen;
}


// ════════════════════════════════════════
// AUTH — Étape 1 : générer l'URL Google
// ════════════════════════════════════════
app.get('/auth/url', authLimiter, (req, res) => {
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

// ════════════════════════════════════════
// AUTH — Étape 2 : callback Google
// ════════════════════════════════════════
app.get('/auth/callback', authLimiter, async (req, res) => {
  const { code } = req.query;
  if (!code || !isValidString(code, 1000)) {
    return res.status(400).send('Code manquant ou invalide');
  }

  try {
    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: userInfo } = await oauth2.userinfo.get();

    // ── SÉCURITÉ : sessionId aléatoire ────────────────────────────
    // Avant : sessionId = Buffer.from(email).toString('base64')
    // Problème : si quelqu'un connaît l'email d'un utilisateur, il peut
    // construire son sessionId et accéder à ses données.
    // Maintenant : 32 bytes aléatoires = 2^256 combinaisons possibles.
    // Même en testant 1 milliard de clés par seconde, il faudrait des
    // milliards d'années pour trouver une session valide par force brute.
    const sessionId = crypto.randomBytes(32).toString('hex');
    sessions[sessionId] = { tokens, email: userInfo.email, createdAt: Date.now() };

    res.redirect(`https://app.rankbase.fr/?session=${sessionId}&email=${encodeURIComponent(userInfo.email)}`);
  } catch (err) {
    // ── SÉCURITÉ : ne pas exposer l'erreur interne ────────────────
    // err.message peut contenir des détails sur notre stack (URLs internes,
    // noms de variables, etc.) qu'on ne veut pas envoyer au client.
    console.error('[Auth callback] Erreur:', err.message);
    res.status(500).send('Erreur lors de l\'authentification. Veuillez réessayer.');
  }
});

// ════════════════════════════════════════
// AUTH — Vérifier une session
// ════════════════════════════════════════
app.get('/auth/check', (req, res) => {
  const { session } = req.query;
  if (!session || !sessions[session]) {
    return res.json({ connected: false });
  }
  res.json({ connected: true, email: sessions[session].email });
});

// ════════════════════════════════════════
// AUTH — Déconnexion
// ════════════════════════════════════════
app.post('/auth/logout', (req, res) => {
  const { session } = req.body;
  if (session && sessions[session]) delete sessions[session];
  res.json({ ok: true });
});

// ════════════════════════════════════════
// USER — Profil + plan (stub Supabase)
// ════════════════════════════════════════
//
// TODO Supabase : remplacer le return par :
//   const { data, error } = await supabase
//     .from('users')
//     .select('email, plan')
//     .eq('email', sessions[session].email)
//     .single();
//   if (error || !data) {
//     await supabase.from('users').upsert({ email, plan: 'free' });
//     return res.json({ email, plan: 'free' });
//   }
//   return res.json({ email: data.email, plan: data.plan });
//
app.get('/user/me', (req, res) => {
  const { session } = req.query;
  if (!session || !sessions[session]) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  const { email } = sessions[session];
  // ⚠️ STUB : plan hardcodé 'free' — à remplacer par Supabase
  res.json({ email, plan: 'premium' });
});


// ════════════════════════════════════════
// GSC — Liste des sites
// ════════════════════════════════════════
app.get('/gsc/sites', async (req, res) => {
  const client = getClientFromSession(req.query.session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  try {
    const sc = google.webmasters({ version: 'v3', auth: client });
    const { data } = await sc.sites.list();
    const sites = (data.siteEntry || []).map(s => ({
      url: s.siteUrl,
      permissionLevel: s.permissionLevel,
    }));
    res.json({ sites });
  } catch (err) {
    console.error('[GSC sites]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer les sites Search Console.' });
  }
});

// ════════════════════════════════════════
// GSC — Données de positions (mots-clés)
// ════════════════════════════════════════
app.post('/gsc/keywords', async (req, res) => {
  const { session, siteUrl, startDate, endDate, rowLimit = 50, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  // Validation de siteUrl
  if (!isValidString(siteUrl, 300)) {
    return res.status(400).json({ error: 'URL de site invalide.' });
  }

  const effectiveDays = days === 1 ? 3 : days === 3 ? 5 : days;
  const end = endDate || new Date().toISOString().split('T')[0];
  const start = startDate || new Date(Date.now() - effectiveDays * 86400000).toISOString().split('T')[0];

  // Limiter rowLimit pour éviter des requêtes trop lourdes
  const safeRowLimit = Math.min(parseInt(rowLimit) || 50, 200);

  try {
    const sc = google.webmasters({ version: 'v3', auth: client });

    const { data } = await sc.searchanalytics.query({
      siteUrl,
      requestBody: {
        startDate: start,
        endDate: end,
        searchType: 'web',
        dimensions: ['query'],
        rowLimit: safeRowLimit,
      },
    });

    const { data: totalsData } = await sc.searchanalytics.query({
      siteUrl,
      requestBody: {
        startDate: start,
        endDate: end,
        searchType: 'web',
        dimensions: [],
        rowLimit: 1,
      },
    });

    const keywords = (data.rows || []).map(row => ({
      keyword: row.keys[0],
      clicks: row.clicks,
      impressions: row.impressions,
      ctr: parseFloat((row.ctr * 100).toFixed(1)),
      position: parseFloat(row.position.toFixed(1)),
    }));

    const totalsRow = (totalsData.rows || [])[0];
    const totals = totalsRow ? {
      clicks: totalsRow.clicks,
      impressions: totalsRow.impressions,
      ctr: parseFloat((totalsRow.ctr * 100).toFixed(1)),
      position: parseFloat(totalsRow.position.toFixed(1)),
    } : null;

    const prevEnd = new Date(Date.now() - effectiveDays * 86400000).toISOString().split('T')[0];
    const prevStart = new Date(Date.now() - effectiveDays * 2 * 86400000).toISOString().split('T')[0];

    let prevMap = {};
    try {
      const { data: prevData } = await sc.searchanalytics.query({
        siteUrl,
        requestBody: {
          startDate: prevStart,
          endDate: prevEnd,
          searchType: 'web',
          dimensions: ['query'],
          rowLimit: safeRowLimit,
        },
      });
      (prevData.rows || []).forEach(row => {
        prevMap[row.keys[0]] = parseFloat(row.position.toFixed(1));
      });
    } catch(e) { /* période précédente optionnelle */ }

    const keywordsWithDelta = keywords.map(k => {
      const prevPos = prevMap[k.keyword] || null;
      const delta = prevPos !== null ? parseFloat((prevPos - k.position).toFixed(1)) : 0;
      return { ...k, prevPosition: prevPos, delta };
    });

    res.json({ keywords: keywordsWithDelta, totals, period: { start, end } });
  } catch (err) {
    console.error('[GSC keywords]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer les mots-clés.' });
  }
});

// ════════════════════════════════════════
// GSC — Évolution d'un mot-clé (courbe)
// ════════════════════════════════════════
app.post('/gsc/keyword-trend', async (req, res) => {
  const { session, siteUrl, keyword, days = 30 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  if (!isValidString(siteUrl, 300) || !isValidString(keyword, 300)) {
    return res.status(400).json({ error: 'Paramètres invalides.' });
  }

  const end = new Date().toISOString().split('T')[0];
  const start = new Date(Date.now() - Math.min(days, 90) * 86400000).toISOString().split('T')[0];

  try {
    const sc = google.webmasters({ version: 'v3', auth: client });
    const { data } = await sc.searchanalytics.query({
      siteUrl,
      requestBody: {
        startDate: start,
        endDate: end,
        dimensions: ['date', 'query'],
        rowLimit: 1000,
        dimensionFilterGroups: [{
          filters: [{ dimension: 'query', operator: 'equals', expression: keyword }]
        }],
      },
    });

    const trend = (data.rows || []).map(row => ({
      date: row.keys[0],
      position: parseFloat(row.position.toFixed(1)),
      clicks: row.clicks,
      impressions: row.impressions,
    }));

    res.json({ keyword, trend });
  } catch (err) {
    console.error('[GSC trend]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer la tendance.' });
  }
});

// ════════════════════════════════════════
// GSC — Opportunités (positions 8-20)
// ════════════════════════════════════════
app.post('/gsc/opportunities', async (req, res) => {
  const { session, siteUrl, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  if (!isValidString(siteUrl, 300)) {
    return res.status(400).json({ error: 'URL de site invalide.' });
  }

  const end = new Date().toISOString().split('T')[0];
  const start = new Date(Date.now() - Math.min(days, 90) * 86400000).toISOString().split('T')[0];

  try {
    const sc = google.webmasters({ version: 'v3', auth: client });
    const { data } = await sc.searchanalytics.query({
      siteUrl,
      requestBody: {
        startDate: start,
        endDate: end,
        searchType: 'web',
        dimensions: ['query', 'page'],
        rowLimit: 200,
      },
    });

    const opportunities = (data.rows || [])
      .filter(row => row.position >= 8 && row.position <= 20)
      .map(row => ({
        keyword: row.keys[0],
        page: row.keys[1],
        position: parseFloat(row.position.toFixed(1)),
        clicks: row.clicks,
        impressions: row.impressions,
        ctr: parseFloat((row.ctr * 100).toFixed(1)),
        potential: Math.round(((20 - row.position) / 12) * 8),
      }))
      .sort((a, b) => b.impressions - a.impressions);

    res.json({ opportunities });
  } catch (err) {
    console.error('[GSC opportunities]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer les opportunités.' });
  }
});

// ════════════════════════════════════════
// GA4 — Liste des propriétés
// ════════════════════════════════════════
app.get('/ga4/properties', async (req, res) => {
  const client = getClientFromSession(req.query.session);
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
        const { data } = await analyticsAdmin.properties.list({
          filter: `parent:accounts/${accountId}`
        });
        (data.properties || []).forEach(p => {
          allProperties.push({
            id: p.name.replace('properties/', ''),
            name: p.displayName,
            url: p.websiteUri || '',
            account: account.displayName,
          });
        });
      } catch(e) {
        console.error('[GA4 properties] Compte', account.name, e.message);
      }
    }

    res.json({ properties: allProperties });
  } catch (err) {
    console.error('[GA4 properties]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer les propriétés Analytics.' });
  }
});

// ════════════════════════════════════════
// GA4 — Données comportementales
// ════════════════════════════════════════
app.post('/ga4/behavior', async (req, res) => {
  const { session, propertyId, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  if (!isValidString(String(propertyId), 50)) {
    return res.status(400).json({ error: 'PropertyId invalide.' });
  }

  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });
    const { data } = await analyticsData.properties.runReport({
      property: `properties/${propertyId}`,
      requestBody: {
        dateRanges: [{ startDate: `${Math.min(days, 90)}daysAgo`, endDate: 'today' }],
        dimensions: [{ name: 'pagePath' }, { name: 'sessionDefaultChannelGroup' }],
        metrics: [
          { name: 'sessions' },
          { name: 'engagedSessions' },
          { name: 'averageSessionDuration' },
          { name: 'screenPageViewsPerSession' },
        ],
        dimensionFilter: {
          filter: {
            fieldName: 'sessionDefaultChannelGroup',
            stringFilter: { matchType: 'CONTAINS', value: 'Organic' },
          },
        },
        orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
        limit: 100,
      },
    });

    const pageMap = {};
    (data.rows || []).forEach(row => {
      const page = row.dimensionValues[0].value;
      const sessions = parseInt(row.metricValues[0].value) || 0;
      const engagedSessions = parseInt(row.metricValues[1].value) || 0;
      const avgDuration = parseFloat(row.metricValues[2].value) || 0;
      const pagesPerSession = parseFloat(row.metricValues[3].value) || 0;
      const bounceRate = sessions > 0
        ? parseFloat(((1 - engagedSessions / sessions) * 100).toFixed(1))
        : 0;
      if (!pageMap[page] || sessions > pageMap[page].sessions) {
        pageMap[page] = { page, sessions, bounceRate, avgDuration, pagesPerSession };
      }
    });

    const pages = Object.values(pageMap)
      .sort((a, b) => b.sessions - a.sessions)
      .slice(0, 50);

    res.json({ pages });
  } catch (err) {
    console.error('[GA4 behavior]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer les données Analytics.' });
  }
});

// ════════════════════════════════════════
// AI — Analyse SEO
// ════════════════════════════════════════
// ── SÉCURITÉ : route protégée par session + rate limit ────────────
// Avant : accessible sans être connecté — n'importe qui pouvait
// consommer ta clé OpenRouter gratuitement.
// Maintenant : session valide obligatoire + max 10 appels/heure/IP.
app.post('/ai/analyze', aiLimiter, async (req, res) => {
  // Vérification de session obligatoire
  const { session, gscData, ga4Data, siteUrl } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  if (!isValidString(siteUrl, 300)) {
    return res.status(400).json({ error: 'URL de site invalide.' });
  }

  // Construire le prompt en gérant proprement les données vides
  const hasGainers      = Array.isArray(gscData?.gainers)      && gscData.gainers.length > 0;
  const hasLosers       = Array.isArray(gscData?.losers)        && gscData.losers.length > 0;
  const hasLowCtr       = Array.isArray(gscData?.lowCtr)        && gscData.lowCtr.length > 0;
  const hasOpportunities = Array.isArray(gscData?.opportunities) && gscData.opportunities.length > 0;
  const hasHighBounce   = Array.isArray(ga4Data?.highBounce)    && ga4Data.highBounce.length > 0;
  const hasBestPages    = Array.isArray(ga4Data?.bestPages)     && ga4Data.bestPages.length > 0;

  const prompt = `Tu es un expert SEO. Analyse ces données et fournis un rapport concis en français.

Site : ${siteUrl}

Données Search Console (7 derniers jours) :
- Mots-clés en progression : ${hasGainers ? JSON.stringify(gscData.gainers.slice(0,5)) : 'Aucun mot-clé en progression détecté sur cette période.'}
- Mots-clés en recul : ${hasLosers ? JSON.stringify(gscData.losers.slice(0,5)) : 'Aucun mot-clé en recul détecté.'}
- CTR faibles (position < 10 mais CTR < 3%) : ${hasLowCtr ? JSON.stringify(gscData.lowCtr.slice(0,5)) : 'Aucun problème de CTR détecté.'}
- Opportunités (pos 8-20) : ${hasOpportunities ? JSON.stringify(gscData.opportunities.slice(0,5)) : 'Aucune opportunité détectée.'}

Données Analytics (trafic organique) :
- Pages avec fort rebond (> 70%) : ${hasHighBounce ? JSON.stringify(ga4Data.highBounce.slice(0,5)) : 'Aucune page à fort rebond détectée.'}
- Meilleures pages (rebond < 40%) : ${hasBestPages ? JSON.stringify(ga4Data.bestPages.slice(0,3)) : 'Aucune donnée disponible.'}

RÈGLES :
- Si une section n'a pas de données, dis-le clairement et positivement.
- Ne tire JAMAIS de conclusion négative à partir d'une absence de données.
- Ne commente que ce qui est présent dans les données fournies.

Réponds avec 4 sections séparées par ### :
### Gains — Ce qui progresse et pourquoi
### Problèmes — Ce qui recule ou déçoit (CTR faible, rebond élevé)
### Opportunités — Les 3 mots-clés à prioriser cette semaine
### Actions — 3 actions concrètes à faire maintenant (courtes et précises)

Sois direct, concis, actionnable. Pas de blabla.`;

  try {
    const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: process.env.OPENROUTER_MODEL || 'openai/gpt-4o-mini',
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }],
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://app.rankbase.fr',
        'X-Title': 'Rankup SEO',
      },
      timeout: 30000,  // timeout 30s pour éviter que la requête reste bloquée indéfiniment
    });

    const content = response.data.choices[0].message.content;
    res.json({ content });
  } catch (err) {
    console.error('[AI analyze]', err.message);
    res.status(500).json({ error: 'Impossible de générer l\'analyse. Réessayez dans quelques instants.' });
  }
});

// ════════════════════════════════════════
// GA4 — Pays + Devices
// ════════════════════════════════════════
app.post('/ga4/geo-devices', async (req, res) => {
  const { session, propertyId, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  if (!isValidString(String(propertyId), 50)) {
    return res.status(400).json({ error: 'PropertyId invalide.' });
  }

  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });

    const [countryResp, deviceResp] = await Promise.all([
      analyticsData.properties.runReport({
        property: `properties/${propertyId}`,
        requestBody: {
          dateRanges: [{ startDate: `${Math.min(days, 90)}daysAgo`, endDate: 'today' }],
          dimensions: [{ name: 'country' }],
          metrics: [{ name: 'sessions' }],
          dimensionFilter: {
            filter: { fieldName: 'sessionDefaultChannelGroup', stringFilter: { matchType: 'CONTAINS', value: 'Organic' } }
          },
          orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
          limit: 8,
        },
      }),
      analyticsData.properties.runReport({
        property: `properties/${propertyId}`,
        requestBody: {
          dateRanges: [{ startDate: `${Math.min(days, 90)}daysAgo`, endDate: 'today' }],
          dimensions: [{ name: 'deviceCategory' }],
          metrics: [{ name: 'sessions' }],
          dimensionFilter: {
            filter: { fieldName: 'sessionDefaultChannelGroup', stringFilter: { matchType: 'CONTAINS', value: 'Organic' } }
          },
          orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
          limit: 5,
        },
      }),
    ]);

    const countries = (countryResp.data.rows || []).map(r => ({
      country: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value),
    }));

    const devices = (deviceResp.data.rows || []).map(r => ({
      device: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value),
    }));

    res.json({ countries, devices });
  } catch (err) {
    console.error('[GA4 geo-devices]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer les données géographiques.' });
  }
});

// ════════════════════════════════════════
// GA4 — Données temps réel
// ════════════════════════════════════════
app.post('/ga4/realtime', async (req, res) => {
  const { session, propertyId } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  if (!isValidString(String(propertyId), 50)) {
    return res.status(400).json({ error: 'PropertyId invalide.' });
  }

  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });

    const [activeUsers, pageViews, countries] = await Promise.all([
      analyticsData.properties.runRealtimeReport({
        property: `properties/${propertyId}`,
        requestBody: { metrics: [{ name: 'activeUsers' }] },
      }),
      analyticsData.properties.runRealtimeReport({
        property: `properties/${propertyId}`,
        requestBody: {
          dimensions: [{ name: 'unifiedPagePathScreen' }],
          metrics: [{ name: 'activeUsers' }],
          orderBys: [{ metric: { metricName: 'activeUsers' }, desc: true }],
          limit: 10,
        },
      }),
      analyticsData.properties.runRealtimeReport({
        property: `properties/${propertyId}`,
        requestBody: {
          dimensions: [{ name: 'country' }],
          metrics: [{ name: 'activeUsers' }],
          orderBys: [{ metric: { metricName: 'activeUsers' }, desc: true }],
          limit: 5,
        },
      }),
    ]);

    const totalActive = parseInt(
      (activeUsers.data.rows || [{ metricValues: [{ value: '0' }] }])[0]?.metricValues[0]?.value || 0
    );

    const pages = (pageViews.data.rows || []).map(r => ({
      page: r.dimensionValues[0].value,
      users: parseInt(r.metricValues[0].value),
    }));

    const topCountries = (countries.data.rows || []).map(r => ({
      countryId: r.dimensionValues[0].value,
      users: parseInt(r.metricValues[0].value),
    }));

    res.json({ totalActive, pages, countries: topCountries, timestamp: Date.now() });
  } catch (err) {
    console.error('[GA4 realtime]', err.message);
    res.status(500).json({ error: 'Impossible de récupérer les données temps réel.' });
  }
});

// ════════════════════════════════════════
// Sanity check
// ════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({ status: 'Rankup backend OK', version: '1.1.0' });
});

// ── Gestion des routes inexistantes ─────────────────────────────
// Retourner un 404 propre au lieu de laisser Express envoyer sa page HTML par défaut
app.use((req, res) => {
  res.status(404).json({ error: 'Route introuvable.' });
});

// ── Gestion globale des erreurs non catchées ─────────────────────
// Filet de sécurité : si une route oublie un try/catch, Express attrape
// l'erreur ici et renvoie un 500 propre au lieu de crasher le serveur.
app.use((err, req, res, next) => {
  console.error('[Erreur non catchée]', err.message);
  res.status(500).json({ error: 'Erreur interne du serveur.' });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`\n🚀 Rankup backend démarré sur http://localhost:${PORT}`);
  console.log(`   Auth URL : http://localhost:${PORT}/auth/url`);
  console.log(`   Callback : http://localhost:${PORT}/auth/callback\n`);
});
