# Branchement Supabase — Rankup

Guide de migration du stub mémoire vers Supabase + Stripe.

---

## 1. Créer le projet Supabase

1. Créer un compte sur [supabase.com](https://supabase.com)
2. Créer un nouveau projet
3. Récupérer dans **Settings → API** :
   - `Project URL` → `SUPABASE_URL`
   - `anon/public key` → `SUPABASE_ANON_KEY`
   - `service_role key` → `SUPABASE_SERVICE_KEY` (⚠️ secret, backend uniquement)

---

## 2. Créer la table `users`

Dans **SQL Editor** de Supabase, exécuter :

```sql
create table users (
  id uuid default gen_random_uuid() primary key,
  email text unique not null,
  plan text not null default 'free',         -- 'free' | 'premium'
  stripe_customer_id text,
  stripe_subscription_id text,
  plan_expires_at timestamptz,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Index sur email pour les lookups rapides
create index users_email_idx on users(email);

-- Mise à jour auto de updated_at
create or replace function update_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger users_updated_at
  before update on users
  for each row execute function update_updated_at();
```

---

## 3. Installer le SDK Supabase dans le backend

```bash
cd rankup-backend
npm install @supabase/supabase-js
```

---

## 4. Ajouter les variables d'environnement

Dans `.env` :

```env
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 5. Initialiser Supabase dans server.js

En haut de `server.js`, après les imports existants :

```javascript
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY  // service key = accès total, backend uniquement
);
```

---

## 6. Remplacer la route `/user/me`

Chercher dans `server.js` le commentaire `// TODO Supabase` et remplacer le return stub par :

```javascript
app.get('/user/me', async (req, res) => {
  const { session } = req.query;
  if (!session || !sessions[session]) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  const { email } = sessions[session];

  try {
    // Chercher l'utilisateur en BDD
    let { data, error } = await supabase
      .from('users')
      .select('email, plan, plan_expires_at')
      .eq('email', email)
      .single();

    if (error || !data) {
      // Première connexion — créer l'utilisateur
      await supabase.from('users').upsert({ email, plan: 'free' });
      return res.json({ email, plan: 'free' });
    }

    // Vérifier expiration du plan
    if (data.plan === 'premium' && data.plan_expires_at && new Date(data.plan_expires_at) < new Date()) {
      await supabase.from('users').update({ plan: 'free' }).eq('email', email);
      return res.json({ email, plan: 'free' });
    }

    res.json({ email: data.email, plan: data.plan });
  } catch(err) {
    console.error('Erreur /user/me:', err.message);
    res.json({ email, plan: 'free' }); // fallback gracieux
  }
});
```

---

## 7. Branchement Stripe (webhooks)

Créer une route `/webhooks/stripe` qui écoute :
- `checkout.session.completed` → passer `plan: 'premium'`
- `customer.subscription.deleted` → repasser `plan: 'free'`
- `invoice.payment_failed` → repasser `plan: 'free'`

```javascript
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  const session = event.data.object;

  if (event.type === 'checkout.session.completed') {
    const email = session.customer_email;
    await supabase.from('users').update({
      plan: 'premium',
      stripe_customer_id: session.customer,
      stripe_subscription_id: session.subscription,
    }).eq('email', email);
  }

  if (event.type === 'customer.subscription.deleted' || event.type === 'invoice.payment_failed') {
    const customer = await stripe.customers.retrieve(session.customer);
    await supabase.from('users').update({ plan: 'free' }).eq('email', customer.email);
  }

  res.json({ received: true });
});
```

---

## 8. Checklist finale avant mise en prod

- [ ] Variables d'environnement Supabase dans `.env`
- [ ] Route `/user/me` mise à jour
- [ ] Webhook Stripe configuré
- [ ] RLS (Row Level Security) activé sur la table `users` dans Supabase
- [ ] Tester un cycle complet : inscription → paiement → accès premium → résiliation → retour free
