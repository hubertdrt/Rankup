require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const axios = require('axios');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── Sessions en mémoire (remplacer par Redis/DB en prod) ──
const sessions = {};

// ── OAuth2 Client ──
function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

// ════════════════════════════════════════
// AUTH — Étape 1 : générer l'URL Google
// ════════════════════════════════════════
app.get('/auth/url', (req, res) => {
  const oauth2Client = getOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',      // pour obtenir un refresh_token
    prompt: 'consent',           // force l'affichage du consentement
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
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Code manquant');

  try {
    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Récupérer l'email de l'utilisateur
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data: userInfo } = await oauth2.userinfo.get();

    // Stocker en session mémoire (clé = email)
    const sessionId = Buffer.from(userInfo.email).toString('base64');
    sessions[sessionId] = { tokens, email: userInfo.email };

    // Rediriger vers le frontend avec le sessionId
    res.redirect(`https://app.rankbase.fr/?session=${sessionId}&email=${encodeURIComponent(userInfo.email)}`);
  } catch (err) {
    console.error('Erreur callback OAuth:', err.message);
    res.status(500).send('Erreur authentification : ' + err.message);
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
// USER — Profil + plan (prêt pour Supabase)
// ════════════════════════════════════════
//
// TODO Supabase : remplacer le return par :
//
//   const { data, error } = await supabase
//     .from('users')
//     .select('email, plan, stripe_customer_id')
//     .eq('email', sessions[session].email)
//     .single();
//
//   if (error || !data) {
//     // Créer l'utilisateur s'il n'existe pas encore
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

  // ── STUB : plan hardcodé 'free' jusqu'à branchement Supabase ──
  res.json({ email, plan: 'premium' });
});

// ── Helper : récupérer le client OAuth d'une session ──
function getClientFromSession(sessionId) {
  const sess = sessions[sessionId];
  if (!sess) return null;
  const oauth2Client = getOAuthClient();
  oauth2Client.setCredentials(sess.tokens);
  return oauth2Client;
}

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
    console.error('Erreur GSC sites:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// GSC — Données de positions (mots-clés)
// ════════════════════════════════════════
app.post('/gsc/keywords', async (req, res) => {
  const { session, siteUrl, startDate, endDate, rowLimit = 50, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  // Dates : priorité startDate/endDate, sinon days
  // Pour 24h/3j : GSC a 2-4j de délai, on prend une fenêtre plus large et on avertit
  const effectiveDays = days === 1 ? 3 : days === 3 ? 5 : days;
  const end = endDate || new Date().toISOString().split('T')[0];
  const start = startDate || new Date(Date.now() - effectiveDays * 86400000).toISOString().split('T')[0];

  try {
    const sc = google.webmasters({ version: 'v3', auth: client });

    // Requête 1 : mots-clés détaillés
    const { data } = await sc.searchanalytics.query({
      siteUrl,
      requestBody: {
        startDate: start,
        endDate: end,
        searchType: 'web',
        dimensions: ['query'],
        rowLimit,
      },
    });

    // Requête 2 : totaux globaux (sans dimension = tout le site)
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

    // Totaux réels du site entier
    const totalsRow = (totalsData.rows || [])[0];
    const totals = totalsRow ? {
      clicks: totalsRow.clicks,
      impressions: totalsRow.impressions,
      ctr: parseFloat((totalsRow.ctr * 100).toFixed(1)),
      position: parseFloat(totalsRow.position.toFixed(1)),
    } : null;

    // Requête 3 : période précédente pour calculer l'évolution
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
          rowLimit,
        },
      });
      (prevData.rows || []).forEach(row => {
        prevMap[row.keys[0]] = parseFloat(row.position.toFixed(1));
      });
    } catch(e) { /* période précédente optionnelle */ }

    // Enrichir les keywords avec le delta
    const keywordsWithDelta = keywords.map(k => {
      const prevPos = prevMap[k.keyword] || null;
      const delta = prevPos !== null ? parseFloat((prevPos - k.position).toFixed(1)) : 0;
      return { ...k, prevPosition: prevPos, delta };
    });

    res.json({ keywords: keywordsWithDelta, totals, period: { start, end } });
  } catch (err) {
    console.error('Erreur GSC keywords:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// GSC — Évolution d'un mot-clé (courbe)
// ════════════════════════════════════════
app.post('/gsc/keyword-trend', async (req, res) => {
  const { session, siteUrl, keyword, days = 30 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  const end = new Date().toISOString().split('T')[0];
  const start = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

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
    console.error('Erreur GSC trend:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// GSC — Opportunités (positions 8-20)
// ════════════════════════════════════════
app.post('/gsc/opportunities', async (req, res) => {
  const { session, siteUrl, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  const end = new Date().toISOString().split('T')[0];
  const start = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

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
    console.error('Erreur GSC opportunities:', err.message);
    res.status(500).json({ error: err.message });
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

    // 1. Récupérer les comptes GA4
    const { data: accountsData } = await analyticsAdmin.accounts.list();
    const accounts = accountsData.accounts || [];

    if (accounts.length === 0) {
      return res.json({ properties: [] });
    }

    // 2. Pour chaque compte, récupérer les propriétés
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
        console.error('Erreur propriétés compte', account.name, e.message);
      }
    }

    res.json({ properties: allProperties });
  } catch (err) {
    console.error('Erreur GA4 properties:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// GA4 — Données comportementales
// ════════════════════════════════════════
app.post('/ga4/behavior', async (req, res) => {
  const { session, propertyId, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });
    const { data } = await analyticsData.properties.runReport({
      property: `properties/${propertyId}`,
      requestBody: {
        dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
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

    // Log première ligne pour debug
    if (data.rows && data.rows[0]) {
      console.log('[GA4 debug] première ligne :', JSON.stringify(data.rows[0]));
    }

    // Dédupliquer par page
    const pageMap = {};
    (data.rows || []).forEach(row => {
      const page = row.dimensionValues[0].value;
      const sessions = parseInt(row.metricValues[0].value) || 0;
      const engagedSessions = parseInt(row.metricValues[1].value) || 0;
      const avgDuration = parseFloat(row.metricValues[2].value) || 0;
      const pagesPerSession = parseFloat(row.metricValues[3].value) || 0;

      // Taux de rebond = (sessions non engagées) / sessions * 100
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
    console.error('Erreur GA4 behavior:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// AI — Analyse des variations
// ════════════════════════════════════════
app.post('/ai/analyze', async (req, res) => {
  const { gscData, ga4Data, siteUrl } = req.body;

  const prompt = `Tu es un expert SEO. Analyse ces données et fournis un rapport concis en français.

Site : ${siteUrl}

Données Search Console (7 derniers jours) :
- Mots-clés en progression : ${JSON.stringify(gscData?.gainers?.slice(0,5) || [])}
- Mots-clés en recul : ${JSON.stringify(gscData?.losers?.slice(0,5) || [])}
- CTR faibles (position < 10 mais CTR < 3%) : ${JSON.stringify(gscData?.lowCtr?.slice(0,5) || [])}
- Opportunités (pos 8-20) : ${JSON.stringify(gscData?.opportunities?.slice(0,5) || [])}

Données Analytics (trafic organique) :
- Pages avec fort rebond (> 70%) : ${JSON.stringify(ga4Data?.highBounce?.slice(0,5) || [])}
- Meilleures pages (rebond < 40%) : ${JSON.stringify(ga4Data?.bestPages?.slice(0,3) || [])}

Réponds avec 4 sections bien séparées par ### :
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
    });

    const content = response.data.choices[0].message.content;
    res.json({ content });
  } catch (err) {
    console.error('Erreur OpenRouter:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// GA4 — Pays + Devices
// ════════════════════════════════════════
app.post('/ga4/geo-devices', async (req, res) => {
  const { session, propertyId, days = 28 } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });

    // Pays
    const { data: countryData } = await analyticsData.properties.runReport({
      property: `properties/${propertyId}`,
      requestBody: {
        dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
        dimensions: [{ name: 'country' }],
        metrics: [{ name: 'sessions' }],
        dimensionFilter: {
          filter: { fieldName: 'sessionDefaultChannelGroup', stringFilter: { matchType: 'CONTAINS', value: 'Organic' } }
        },
        orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
        limit: 8,
      },
    });

    // Devices
    const { data: deviceData } = await analyticsData.properties.runReport({
      property: `properties/${propertyId}`,
      requestBody: {
        dateRanges: [{ startDate: `${days}daysAgo`, endDate: 'today' }],
        dimensions: [{ name: 'deviceCategory' }],
        metrics: [{ name: 'sessions' }],
        dimensionFilter: {
          filter: { fieldName: 'sessionDefaultChannelGroup', stringFilter: { matchType: 'CONTAINS', value: 'Organic' } }
        },
        orderBys: [{ metric: { metricName: 'sessions' }, desc: true }],
        limit: 5,
      },
    });

    const countries = (countryData.rows || []).map(r => ({
      country: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value),
    }));

    const devices = (deviceData.rows || []).map(r => ({
      device: r.dimensionValues[0].value,
      sessions: parseInt(r.metricValues[0].value),
    }));

    res.json({ countries, devices });
  } catch (err) {
    console.error('Erreur GA4 geo-devices:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// ════════════════════════════════════════
// GA4 — Données temps réel (30 min)
// ════════════════════════════════════════
app.post('/ga4/realtime', async (req, res) => {
  const { session, propertyId } = req.body;
  const client = getClientFromSession(session);
  if (!client) return res.status(401).json({ error: 'Non connecté' });

  try {
    const analyticsData = google.analyticsdata({ version: 'v1beta', auth: client });

    // Utilisateurs actifs + pages en temps réel
    const [activeUsers, pageViews, countries] = await Promise.all([

      // 1. Total utilisateurs actifs
      analyticsData.properties.runRealtimeReport({
        property: `properties/${propertyId}`,
        requestBody: {
          metrics: [{ name: 'activeUsers' }],
        },
      }),

      // 2. Pages actives
      analyticsData.properties.runRealtimeReport({
        property: `properties/${propertyId}`,
        requestBody: {
          dimensions: [{ name: 'unifiedPagePathScreen' }],
          metrics: [{ name: 'activeUsers' }],
          orderBys: [{ metric: { metricName: 'activeUsers' }, desc: true }],
          limit: 10,
        },
      }),

      // 3. Pays actifs
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

    const totalActive = parseInt((activeUsers.data.rows || [{ metricValues: [{ value: '0' }] }])[0]?.metricValues[0]?.value || 0);

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
    console.error('Erreur GA4 realtime:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════
// Sanity check
// ════════════════════════════════════════
app.get('/', (req, res) => {
  res.json({ status: 'Rankup backend OK', version: '1.0.0' });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`\n🚀 Rankup backend démarré sur http://localhost:${PORT}`);
  console.log(`   Auth URL : http://localhost:${PORT}/auth/url`);
  console.log(`   Callback : http://localhost:${PORT}/auth/callback\n`);
});
