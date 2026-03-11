# Rankup — Guide d'installation

## 1. Prérequis
- Node.js installé (v16+)
- Projet Google Cloud avec OAuth configuré
- Clé OpenRouter (même que Rankly)

## 2. Installation

```bash
cd rankup-backend
npm install
```

## 3. Configuration

Copiez `.env.example` en `.env` et remplissez :

```bash
cp .env.example .env
```

Editez `.env` :
```
GOOGLE_CLIENT_ID=votre_client_id
GOOGLE_CLIENT_SECRET=votre_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3002/auth/callback
OPENROUTER_API_KEY=sk-or-v1-xxxx
OPENROUTER_MODEL=openai/gpt-4o-mini
PORT=3002
SESSION_SECRET=mettez_une_longue_chaine_aleatoire
```

## 4. Lancement

```bash
npm start
```

Le serveur démarre sur http://localhost:3002

## 5. Tester l'auth

Ouvrez dans le navigateur :
```
http://localhost:3002/auth/url
```
Ça retourne une URL Google — copiez-la et ouvrez-la pour tester la connexion.

## 6. Mettre à jour l'URI dans Google Cloud

Dans Google Cloud Console → Identifiants → votre ID client OAuth :
- URI de redirection autorisés : `http://localhost:3002/auth/callback`

## Routes disponibles

| Route | Méthode | Description |
|---|---|---|
| `/auth/url` | GET | Génère l'URL de connexion Google |
| `/auth/callback` | GET | Callback OAuth (appelé par Google) |
| `/auth/check` | GET | Vérifie si une session est valide |
| `/auth/logout` | POST | Déconnexion |
| `/gsc/sites` | GET | Liste des sites GSC |
| `/gsc/keywords` | POST | Mots-clés + positions |
| `/gsc/keyword-trend` | POST | Évolution d'un mot-clé |
| `/gsc/opportunities` | POST | Mots-clés en pos. 8-20 |
| `/ga4/properties` | GET | Liste des propriétés GA4 |
| `/ga4/behavior` | POST | Comportement pages organiques |
| `/ai/analyze` | POST | Analyse IA via OpenRouter |

## Notes

- Les sessions sont stockées en mémoire — elles se perdent au redémarrage du serveur.
  En production, utilisez Redis ou une base de données.
- Le frontend `index.html` doit tourner sur un serveur local (ex: Live Server VS Code sur port 5500)
  pour que le redirect OAuth fonctionne correctement.
