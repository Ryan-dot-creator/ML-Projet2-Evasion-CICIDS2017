# Projet 2 — Attaquer son propre détecteur d'intrusion (CIC-IDS2017)

Module Machine Learning pour la cyber-sécurité — TEK-UP, 2026-2027.
Étude d'**évasion adverse sous contraintes réalistes** contre un détecteur d'intrusion XGBoost, puis évaluation de trois durcissements face à des attaques connues **et inédites**.

| Rôle | Membre | Contenu du notebook |
|---|---|---|
| Défenseur | Hamza Kalai | §2–4 données, découpage chronologique, modèles, seuil par le coût ; §8 défenses D1, D2, D3 |
| Attaquant | Rayen Hassen | §5–7 modèle de menace, perturbations cohérentes, attaque boîte noire ; §9 attaques inédites (fenêtre TCP, étiquette seule, transfert) |
| Commun | les deux | §10 évaluation finale sur le test, §11 rapport |

## Exécution

**Google Colab** : ouvrir `Projet2_Evasion_CICIDS2017.ipynb`, puis *Exécution → Tout exécuter*. Les données (≈ 300 Mo) sont téléchargées automatiquement au premier lancement.

**Machine personnelle** :
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
jupyter nbconvert --to notebook --execute --ExecutePreprocessor.timeout=-1 Projet2_Evasion_CICIDS2017.ipynb
```

- `QUICK = True` (section 1) : exécution réduite en quelques minutes, pour vérifier que tout fonctionne.
- `QUICK = False` : résultats du rapport. Compter environ 1 h sur un CPU à 2 cœurs. Mémoire maximale ≈ 4 Go.

## Données

- **Source officielle** : Canadian Institute for Cybersecurity, CIC-IDS2017, <https://www.unb.ca/cic/datasets/ids-2017.html>. Fichiers `GeneratedLabelledFlows` (*TrafficLabelling*), qui contiennent l'horodatage nécessaire au découpage chronologique.
- **Téléchargement automatique** : miroir Parquet des mêmes fichiers sur Hugging Face (`bvsam/cic-ids-2017`, configuration `traffic_labels`). Le notebook vérifie que l'on retrouve bien les 2 830 743 flux de la version officielle.
- Les données brutes **ne sont pas versionnées** (`data/` est dans `.gitignore`).
- Citation : I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, ICISSP 2018.

## Protocole (résumé)

1. Nettoyage : lignes vides, inf/NaN, durées négatives, **doublons exacts supprimés avant le découpage**, lignes ambiguës ; variables identifiantes (IP, ports, `Flow ID`, horodatage) exclues.
2. **Découpage chronologique par épisode** (fichier × famille) : 60 % les plus anciens / 20 % / 20 % les plus récents.
3. Sélection de variables, normalisation et sous-échantillonnage appris sur le **train seulement** ; validation et test gardent la prévalence naturelle.
4. Réglage par **validation croisée temporelle par blocs** ; seuil d'alerte choisi sur la validation par une règle de coût (FN = 10 × FP).
5. Le test n'est utilisé **qu'une fois** (section 10).

## Résultats principaux (test, `QUICK = False`)

| Détecteur | F1 normal | Fausses alertes / jour | Rappel sans attaque | Attaque T1 ε = 5 | Action inédite T2 ε = 5 |
|---|---|---|---|---|---|
| XGBoost initial | 0,992 | 578 | 0,897 | 0,719 | 0,214 |
| D1 entraînement adverse | 0,992 | 584 | 0,898 | 0,885 | 0,478 |
| D2 variables non manipulables | 0,979 | 2 316 | 0,879 | 0,879 | 0,335 |
| D3 contraintes monotones | 0,987 | 868 | 0,894 | 0,776 | 0,222 |

Rappel sous attaque équilibré par famille (1 112 flux de test). Détails, limites et conformité au cahier des charges : section 11 du notebook.

## Reproductibilité

- Graine unique `SEED = 42` ; toutes les graines secondaires en dérivent. Les attaques sont répétées sur 3 graines.
- Versions testées : voir `requirements-lock.txt` (exactes) et `requirements.txt` (plages compatibles).
- Sorties : `resultats_projet2.json` (tous les chiffres du rapport) et les figures `fig_*.png`.

## Organisation du dépôt

Le code est écrit dans `src/`, **un fichier par rôle et par partie** (format jupytext « percent »). Le notebook est assemblé à partir de ces fichiers ; l'historique Git montre ainsi la contribution de chacun.

| Fichier | Rôle | Sections du notebook |
|---|---|---|
| `src/00_commun_entete_config.py` | commun | 0–1 problématique, configuration |
| `src/10_defenseur_donnees_protocole_modeles.py` | défenseur (Hamza Kalai) | 2–4 données, découpage, modèles, seuil |
| `src/20_attaquant_menace_perturbations_attaque.py` | attaquant (Rayen Hassen) | 5–7 modèle de menace, perturbations, attaque |
| `src/30_defenseur_defenses.py` | défenseur (Hamza Kalai) | 8 défenses D1, D2, D3 |
| `src/40_attaquant_attaques_inedites.py` | attaquant (Rayen Hassen) | 9 attaques inédites, substitut |
| `src/50_commun_evaluation_finale.py` | commun | 10 évaluation finale sur le test |
| `src/60_commun_rapport.py` | commun | 11 rapport |

```
.
├── src/                               # sources par rôle (ci-dessus)
├── build_notebook.py                  # assemble (et exécute avec --execute) le notebook
├── Projet2_Evasion_CICIDS2017.ipynb   # notebook assemblé et exécuté (rendu)
├── results/                           # resultats_projet2.json + figures
├── README.md, requirements*.txt, .gitignore
```

Régénérer le notebook après une modification : `python build_notebook.py --execute`.

## Éthique

Données publiques uniquement. Aucune attaque contre un système réel. Les attaques modifient des vecteurs de statistiques de flux pour mesurer les faiblesses du détecteur et le renforcer.
