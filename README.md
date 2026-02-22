# 🛡️ CybeAttack-Analyse — Tableau de Bord de Détection de Cyberattaques

Application web Flask permettant de détecter automatiquement les cyberattaques dans des fichiers de logs grâce à un **système de détection à deux niveaux** :

1. **Détection par règles** — expressions régulières (regex) ciblant les attaques connues.
2. **Détection par Machine Learning** — classificateur Random Forest entraîné sur des données synthétiques.

---

## 📋 Types d'attaques détectées

| Type d'attaque       | Sévérité   |
|----------------------|------------|
| Injection SQL        | Critique   |
| XSS (Cross-Site Scripting) | Élevée |
| Traversée de chemin  | Élevée     |
| Injection de commandes | Critique |
| Injection LDAP       | Moyenne    |
| Falsification de logs | Moyenne   |
| Suspect (ML)         | Moyenne    |

---

## 🗂️ Structure du projet

```
CybeAttack-Analyse/
├── cyber-dashboard/
│   ├── app.py              # Application Flask principale (routes API)
│   ├── config.py           # Configuration (BDD, uploads, clé secrète)
│   ├── detector.py         # Module de détection (regex + Random Forest)
│   ├── models.py           # Modèles SQLAlchemy (ScanLog, Threat)
│   ├── setup_db.py         # Script d'initialisation de la base de données
│   ├── test_upload.py      # Script de test d'upload
│   ├── ml_model.pkl        # Modèle ML pré-entraîné
│   ├── sample_test.log     # Fichier de log d'exemple pour tester
│   ├── requirements.txt    # Dépendances Python
│   ├── templates/
│   │   └── index.html      # Page HTML du tableau de bord
│   ├── static/
│   │   ├── css/            # Feuilles de style
│   │   └── js/             # Scripts JavaScript
│   └── uploads/            # Dossier temporaire pour les fichiers uploadés
└── README.md
```

---

## 🚀 Étapes pour faire fonctionner le projet

### Prérequis

- **Python 3.10+** installé sur votre machine
- **pip** (gestionnaire de paquets Python, inclus avec Python)
- **Git** (optionnel, pour cloner le dépôt)

---

### Étape 1 — Cloner le dépôt (ou télécharger le zip)

```bash
git clone https://github.com/DaPvssy/CybeAttack-Analyse.git
cd CybeAttack-Analyse
```

---

### Étape 2 — Créer un environnement virtuel

```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

> [!NOTE]
> Après activation, vous devriez voir `(.venv)` au début de votre ligne de commande.

---

### Étape 3 — Installer les dépendances

```bash
cd cyber-dashboard
pip install -r requirements.txt
```

Les dépendances principales sont :

| Paquet             | Rôle                                    |
|--------------------|-----------------------------------------|
| `flask`            | Framework web                           |
| `flask-sqlalchemy` | ORM pour la base de données             |
| `flask-cors`       | Gestion des requêtes cross-origin       |
| `scikit-learn`     | Modèle de Machine Learning              |
| `joblib`           | Sauvegarde/chargement du modèle ML      |
| `numpy`            | Calculs numériques                      |
| `pymysql`          | Connecteur MySQL (optionnel)            |

---

### Étape 4 — Initialiser la base de données

```bash
python setup_db.py
```

> Par défaut, l'application utilise **SQLite** — aucune configuration supplémentaire n'est nécessaire. Le fichier de base de données sera créé automatiquement dans `cyber-dashboard/instance/cyber_dashboard.db`.

---

### Étape 5 — Lancer l'application

```bash
python app.py
```

Vous devriez voir :

```
🛡️  Cybersecurity Dashboard running at http://127.0.0.1:5000
```

---

### Étape 6 — Ouvrir le tableau de bord

Ouvrez votre navigateur et allez à :

👉 **http://127.0.0.1:5000**

---

### Étape 7 — Tester avec un fichier de log

Un fichier d'exemple est fourni pour tester l'application :

1. Cliquez sur le bouton **Upload** dans le tableau de bord.
2. Sélectionnez le fichier `sample_test.log` (dans `cyber-dashboard/`).
3. Les résultats de l'analyse s'afficheront avec les menaces détectées.

> [!TIP]
> Vous pouvez aussi tester avec vos propres fichiers `.txt`, `.log` ou `.csv` (taille max : 16 Mo).

---

## ⚙️ Configuration avancée (optionnel)

### Utiliser MySQL au lieu de SQLite

Définissez la variable d'environnement `DATABASE_URL` avant de lancer l'application :

```bash
# Windows (PowerShell)
$env:DATABASE_URL = "mysql+pymysql://utilisateur:motdepasse@localhost/cyber_dashboard"

# macOS / Linux
export DATABASE_URL="mysql+pymysql://utilisateur:motdepasse@localhost/cyber_dashboard"
```

Puis réinitialisez la base de données :

```bash
python setup_db.py
```

### Ré-entraîner le modèle ML

Si vous souhaitez ré-entraîner le modèle de Machine Learning :

```python
from detector import train_model
train_model()
```

---

## 🔗 Points d'accès de l'API

| Méthode | URL                    | Description                              |
|---------|------------------------|------------------------------------------|
| `GET`   | `/`                    | Page principale du tableau de bord       |
| `POST`  | `/api/upload`          | Uploader un fichier de log pour analyse  |
| `GET`   | `/api/history`         | Historique des 20 derniers scans         |
| `GET`   | `/api/scan/<scan_id>`  | Détails d'un scan spécifique             |

---

## 🛠️ Technologies utilisées

- **Backend** : Python, Flask, SQLAlchemy
- **Frontend** : HTML, CSS, JavaScript
- **Machine Learning** : scikit-learn (Random Forest)
- **Base de données** : SQLite (par défaut) / MySQL (optionnel)
