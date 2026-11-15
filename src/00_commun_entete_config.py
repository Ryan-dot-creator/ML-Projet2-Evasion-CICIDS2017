# %% [markdown]
# # Projet 2 — Attaquer son propre détecteur d'intrusion
# **Évasion adverse sous contraintes réalistes sur CIC-IDS2017** · Python, scikit-learn, XGBoost · exécutable de haut en bas (Google Colab CPU ou machine personnelle)
#
# | Rôle | Membre | Sections |
# |---|---|---|
# | **Défenseur** | **Hamza Kalai** | 2 à 4 (données, protocole, modèles, seuil), 8 (défenses D1, D2, D3) |
# | **Attaquant** | **Rayen Hassen** | 5 à 7 (modèle de menace, perturbations, attaques), 9 (attaques inédites, étiquette seule, transfert) |
# | Commun | les deux | 10 (évaluation finale), 11 (rapport) |
#
# Pour limiter le biais d'un binôme qui « connaît » les deux côtés, l'attaquant n'utilise que ce que le modèle de menace (section 5) l'autorise à savoir, et le défenseur choisit ses défenses **avant** de voir les attaques inédites de la section 9.
#
# ## 0. Problématique
# Les détecteurs d'intrusion appris sur des jeux publics affichent souvent plus de 99 % de F1. Ces scores sont mesurés contre des attaques qui **ne cherchent pas à se cacher**. Un adversaire réel choisit son trafic : il peut ralentir, remplir ses paquets, insérer des pauses ou régler sa fenêtre TCP pour être classé « légitime » **sans perdre l'efficacité de son attaque**.
#
# **Questions de recherche**
# 1. **Q1 — Vulnérabilité.** Quel est le taux d'évasion d'un adversaire réaliste (variables contraintes, 1 000 requêtes au plus par flux) et comment le rappel chute-t-il avec l'amplitude ε autorisée ?
# 2. **Q2 — Réalisme.** Les flux modifiés restent-ils physiquement cohérents ? De combien une attaque sans contrainte surestime-t-elle la menace ?
# 3. **Q3 — Défense.** Trois durcissements (entraînement adverse, variables non manipulables, contraintes monotones) : quel gain de robustesse, à quel coût sur les performances normales ?
# 4. **Q4 — Généralisation de la défense.** Les défenses résistent-elles à une attaque **qu'elles n'ont pas vue** : action inédite (fenêtre TCP), attaquant qui ne voit que la décision, attaque par transfert sans accès au modèle ?
#
# > **Éthique.** Données publiques uniquement (CIC-IDS2017), aucune attaque contre un système réel. Les attaques agissent sur des vecteurs de statistiques de flux, pas sur du trafic réel. Elles servent à mesurer les faiblesses du détecteur pour mieux le protéger.

# %% [markdown]
# ## 1. Configuration et reproductibilité
# - **Données** : téléchargées automatiquement (≈ 300 Mo) depuis un miroir Hugging Face des fichiers officiels `GeneratedLabelledFlows` (version *TrafficLabelling*, qui contient l'horodatage indispensable au découpage chronologique). Source officielle : Canadian Institute for Cybersecurity, <https://www.unb.ca/cic/datasets/ids-2017.html> (Sharafaldin et al., 2018). Les données brutes ne sont **pas** versionnées dans Git.
# - `QUICK = True` : version réduite (quelques minutes) pour vérifier que tout s'exécute. `QUICK = False` : résultats du rapport (≈ 60 à 90 min sur un CPU à 2 cœurs).
# - Toutes les graines dérivent de `SEED`. Les versions des bibliothèques sont imprimées ci-dessous et figées dans `requirements.txt`.

# %%
import os, sys, time, json, random, warnings, urllib.request
import numpy as np, pandas as pd
import matplotlib.pyplot as plt
import sklearn, xgboost
from IPython.display import display, Markdown
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, FunctionTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import PredefinedSplit, RandomizedSearchCV, GridSearchCV, train_test_split
from sklearn.metrics import (precision_recall_fscore_support, average_precision_score, roc_auc_score,
                             confusion_matrix, ConfusionMatrixDisplay, precision_recall_curve)
warnings.filterwarnings("ignore", category=UserWarning)
pd.set_option("display.width", 200); pd.set_option("display.max_columns", 30)

SEED = 42
random.seed(SEED); np.random.seed(SEED); os.environ["PYTHONHASHSEED"] = str(SEED)
print("Python", sys.version.split()[0], "| numpy", np.__version__, "| pandas", pd.__version__,
      "| scikit-learn", sklearn.__version__, "| xgboost", xgboost.__version__)

# %%
# ============================== CONFIGURATION ==============================
QUICK          = False
DATA_DIR       = "data/cic-ids2017"        # sur Colab : "/content/drive/MyDrive/ML/cic-ids2017" pour garder le cache
HF_BASE        = "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/traffic_labels/"
SPLIT          = (0.60, 0.20, 0.20)        # fractions chronologiques par épisode : train / validation / test
TRAIN_FRAC     = 0.15                      # sous-échantillonnage du TRAIN uniquement (validation et test restent complets)
MIN_PER_FAMILY = 3000                      # ... mais chaque famille garde au moins min(n, 3000) flux d'entraînement
N_TUNE         = 60_000                    # sous-échantillon du train pour le réglage (validation croisée temporelle)
N_ITER         = 10                        # itérations de recherche aléatoire (RF, XGBoost)
COST_RATIO     = 10                        # coût d'un faux négatif / coût d'un faux positif (choix du seuil, section 4.3)
BUDGET         = 1000                      # requêtes max par flux attaqué (cahier des charges)
CAP_FAMILY     = 100                       # flux attaqués par famille (test final)
EPS_GRID       = [0, 0.1, 0.25, 0.5, 1, 2, 5]
ATTACK_SEEDS   = [0, 1, 2]                 # l'attaque est répétée avec plusieurs graines (moyenne ± écart-type)
EPS_TRAIN_CANDIDATES = [1.0, 3.0]          # amplitudes d'entraînement adverse comparées sur la VALIDATION
HARDEN_ROUNDS  = 2
N_ADV_TRAIN    = 4000
BUDGET_TRAIN   = 200
if QUICK:
    TRAIN_FRAC, MIN_PER_FAMILY, N_TUNE, N_ITER = 0.04, 800, 15_000, 3
    BUDGET, CAP_FAMILY, EPS_GRID, ATTACK_SEEDS = 150, 25, [0, 0.5, 1, 5], [0]
    EPS_TRAIN_CANDIDATES, HARDEN_ROUNDS, N_ADV_TRAIN, BUDGET_TRAIN = [1.0], 1, 1000, 50
CONFIG = {k: v for k, v in globals().items() if k.isupper() and not k.startswith("_")}
print(CONFIG)
