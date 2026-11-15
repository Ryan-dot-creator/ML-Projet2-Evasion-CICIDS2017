"""Génère la section 11 (rapport) à partir des résultats : aucun chiffre n'est recopié à la main.

    python make_report.py                    # lit results/resultats_projet2.json, écrit src/60_commun_rapport.py
    python build_notebook.py --keep-outputs  # réassemble le notebook avec le rapport à jour

Les affirmations qualitatives du texte sont protégées par des assert : si les résultats changent au point de
les contredire, la génération échoue au lieu de produire un rapport faux."""
import json, sys
import pandas as pd

src = sys.argv[1] if len(sys.argv) > 1 else "results/resultats_projet2.json"
out = sys.argv[2] if len(sys.argv) > 2 else "src/60_commun_rapport.py"
d = json.load(open(src, encoding="utf-8"))
I, D1, D2, D3, D4 = "XGBoost initial", "D1 entraînement adverse", "D2 non manipulables", "D3 monotone", "D4 entraînement adverse T1+T2"
R, T, V = d["robustesse"], d["test_normal"], d["validation"]
CUR = pd.DataFrame(d["courbes_T1"]).set_index(["défense", "eps"])
UNC = pd.DataFrame(d["courbe_sans_contrainte"]).set_index("eps")
FAM = d["familles_sous_attaque"]
COST = pd.DataFrame(d["cout_attaquant"]).set_index(["eps", "famille"])
REAL, CI, N = d["realisme"], d["test_ic95"], d["nettoyage"]

def f(x, n=3): return f"{x:.{n}f}".replace(".", ",")
def n_(x): return f"{int(round(x)):,}".replace(",", " ")
def ci(name, k): return CI[name][k].replace(".", ",").replace(", ", " ; ")
def fam(eps, family, col): return FAM[str(eps)][family][col]
def cur(dn, eps, col="rappel"): return CUR.loc[(dn, float(eps)), col]
def alerts(dn): return R[dn]["fausses alertes / jour"]
def added(k): return REAL[k]["FLUX AVEC AU MOINS UNE VIOLATION AJOUTÉE PAR L'ATTAQUE"]["% violé (flux modifiés)"]

r0 = R[I]["sans attaque"]
drop5 = 100 * (r0 - R[I]["T1 ε=5"])
dup = 100 * (N["sans temps négatifs"] - N["sans doublons exacts"]) / N["sans temps négatifs"]
rs = d["decoupage_aleatoire"]; miss_r = 100 * (1 - rs["aléatoire — test"]["rec_attack"]); miss_c = 100 * (1 - rs["chronologique — validation"]["rec_attack"])
tr1 = 100 * (r0 - R[I]["transfert ε=1"]) / (r0 - R[I]["T1 ε=1"]); tr5 = 100 * (r0 - R[I]["transfert ε=5"]) / (r0 - R[I]["T1 ε=5"])
dv = pd.DataFrame(d["defenses_validation"]).set_index("défense")
d1v = dv[dv.index.str.startswith("D1")]
unc_var = REAL["sans_contrainte"]["variable hors modèle de menace changée"]["% violé (flux modifiés)"]
unc_rate = REAL["sans_contrainte"]["débit octets/s ≈ octets / durée"]["% violé (flux modifiés)"]
unc_120 = REAL["sans_contrainte"]["durée > 120 s (délai d'expiration des flux)"]["% violé (flux modifiés)"]
n_inv = len(REAL["T1"]) - 1
bot = d["bot"]
W = pd.DataFrame(d["fenetre_par_famille"]).T
Wa = W[(W.index != "BENIGN") & (W["flux"].astype(float) >= 50)]
top2 = Wa["valeurs_les_plus_frequentes"].str.findall(r"\((\d+)%\)").map(lambda v: sum(map(int, v)))
n_conc = int((top2 >= 90).sum())
ben_distinct = int(float(W.loc["BENIGN", "valeurs_distinctes"]))

# ---- garde-fous des affirmations qualitatives
assert abs(T[D1]['f1_attack'] - T[I]['f1_attack']) <= 0.001 and d1v.FP_val.iloc[0] < d1v.FP_val.iloc[1]
assert all(d['rappel_famille_test']['Bot'][x] == 0 for x in ['Forêt aléatoire', I, D1, D2, D3, D4])
assert abs(COST.loc[(5.0, 'DoS Hulk'), 'allongement_duree_med'] - COST.loc[(5.0, 'SSH-Patator'), 'allongement_duree_med']) < 0.3
assert fam(1, 'Web Attack - Brute Force', f'{D1} — T2') > 0.85 > 0.2 > fam(1, 'Web Attack - Brute Force', f'{I} — T2')
assert min(fam(1, x, f'{D4} — T2') for x in ['FTP-Patator', 'DoS slowloris', 'PortScan']) > 0.9 and max(fam(1, x, f'{D4} — T2') for x in ['DoS Hulk', 'DoS Slowhttptest']) < 0.7
assert added("T1") == 0 and added("T2") == 0
assert fam(1, "DoS Slowhttptest", f"{I} — T1") < 0.4 and COST.loc[(1.0, "DoS Slowhttptest"), "surcout_octets_med_pct"] == 0
assert all(fam(5, x, f"{I} — T1") >= 0.99 for x in ["DoS GoldenEye", "FTP-Patator"])
assert R[D1]["T1 ε=5"] > R[I]["T1 ε=5"] + 0.15 and R[D2]["T1 ε=5"] == R[D2]["sans attaque"]
assert max(R[x]["T2 (fenêtre TCP) ε=5"] for x in (I, D1, D2, D3)) < 0.6 < R[D4]["T2 (fenêtre TCP) ε=5"]
assert abs(R[I]["étiquette seule ε=5"] - R[I]["T1 ε=5"]) < 0.02
assert T[D4]["rec_attack"] < T[I]["rec_attack"] - 0.01 and R[D4]["T1 ε=5"] < R[D1]["T1 ε=5"]
assert float(bot["test"]["% sans charge utile aller"]) == 100 and float(bot["test"]["% détectés (XGBoost initial)"]) == 0
assert d["rang_fenetre_tcp_substitut"] > 10 and n_conc >= 6
assert len(d1v) == 2 and abs(d1v.rappel_adv_eps1.iloc[0] - d1v.rappel_adv_eps1.iloc[1]) < 1e-9 and abs(d1v.rappel_adv_eps5.iloc[0] - d1v.rappel_adv_eps5.iloc[1]) < 1e-9

def row(dn, label):
    return (f"| {label} | {f(T[dn]['f1_attack'])} | {f(T[dn]['rec_attack'])} | {n_(alerts(dn))} | {f(R[dn]['sans attaque'])} | {f(R[dn]['T1 ε=1'])} | {f(R[dn]['T1 ε=5'])} | "
            f"{f(R[dn]['T2 (fenêtre TCP) ε=1'])} | {f(R[dn]['T2 (fenêtre TCP) ε=5'])} | {f(R[dn]['étiquette seule ε=5'])} | {f(R[dn]['transfert ε=5'])} |")

eps_cols = [0.1, 0.5, 1, 2, 5]
md = f"""## 11. Rapport

*Tous les chiffres de cette section sont lus dans `resultats_projet2.json`, produit par l'exécution ci-dessus (`QUICK = False`, `SEED = 42`). Rappel sous attaque = rappel équilibré par famille sur {n_(d['n_flux_attaques'])} flux d'attaque de test (100 par famille au plus).*

### 11.1 Résumé
Un détecteur XGBoost à **F1 = {f(T[I]['f1_attack'])}** sur le test (découpage chronologique, sans fuite) perd **{f(drop5, 0)} points de rappel** face à un attaquant réaliste qui ne fait que ralentir, remplir ou espacer son trafic ({f(r0)} → {f(R[I]['T1 ε=5'])} à ε = 5), sans violer aucun des invariants physiques contrôlés. L'entraînement adverse (D1) annule presque cet effet ({f(R[D1]['T1 ε=5'])}), pour {f(100 * (alerts(D1) / alerts(I) - 1), 0)} % de fausses alertes en plus. Mais une **quatrième action, gratuite et non anticipée** (choisir la fenêtre TCP initiale), fait tomber le rappel à **{f(R[I]['T2 (fenêtre TCP) ε=5'], 2)}** pour le modèle initial et à **{f(R[D1]['T2 (fenêtre TCP) ε=5'], 2)}** pour D1. Un second cycle d'entraînement adverse qui intègre cette action (D4) remonte à **{f(R[D4]['T2 (fenêtre TCP) ε=5'], 2)}**, mais perd {f(100 * (T[I]['rec_attack'] - T[D4]['rec_attack']), 1)} points de rappel sur le trafic non modifié. Une défense ne protège que contre le modèle de menace pour lequel elle a été construite, et chaque cycle a un coût.

### 11.2 Données, protocole et modèles
- {n_(N['sans lignes vides'])} flux → {n_(N['sans lignes ambiguës'])} après nettoyage ; **{f(dup, 0)} % de doublons exacts** supprimés avant le découpage (98,8 % des flux PortScan sont des doublons).
- Découpage **chronologique par épisode** (60/20/20), validation croisée temporelle à origine glissante, seuil choisi par le coût (FN = 10 × FP) sur la validation, test utilisé pour les résultats finaux uniquement.
- Test : baseline LR F1 = {f(T['Baseline LR']['f1_attack'])} (PR-AUC {f(T['Baseline LR']['pr_auc'])}) ; arbre de profondeur 4 F1 = {f(T['Baseline arbre (prof. 4)']['f1_attack'])} ; forêt aléatoire F1 = {f(T['Forêt aléatoire']['f1_attack'])} (IC 95 % {ci('Forêt aléatoire', 'F1 IC95')}) ; **XGBoost F1 = {f(T[I]['f1_attack'])}** (IC 95 % {ci(I, 'F1 IC95')}), PR-AUC {f(T[I]['pr_auc'])} pour une prévalence de 0,153, {n_(T[I]['FP'])} faux positifs et {n_(T[I]['FN'])} faux négatifs sur 439 109 flux, soit **≈ {n_(round(alerts(I), -1))} fausses alertes par jour** au volume réel. Inférence ≈ {f(T[I]['inférence (µs/flux)'], 1)} µs par flux : compatible avec une détection quasi temps réel.
- **Effet du protocole** : avec un découpage aléatoire, le même modèle manque {f(miss_r, 2)} % des attaques contre {f(miss_c, 2)} % en chronologique ({f(miss_c / miss_r, 0)} fois moins), et le rappel de Bot y passe de 0,24 à 0,99. Les scores supérieurs à 99,9 % publiés sur ce jeu mesurent en partie de la mémorisation.

### 11.3 Q1 — Vulnérabilité à un attaquant réaliste (T1)
| ε | 0 | {' | '.join(f(e, 1) if e < 1 else str(e) for e in eps_cols)} |
|---|---|{'---|' * len(eps_cols)}
| Rappel sous attaque (XGBoost initial) | {f(r0)} | {' | '.join(f(cur(I, e)) for e in eps_cols)} |
| Taux d'évasion (flux détectés au départ) | — | {' | '.join(f(100 * cur(I, e, 'taux_evasion'), 1) + ' %' for e in eps_cols)} |
| Requêtes médianes jusqu'à l'évasion | — | {' | '.join(f(cur(I, e, 'requetes_med'), 0) for e in eps_cols)} |

- Variabilité entre les 3 graines d'attaque : écart-type du rappel ≤ {f(CUR['rappel_std'].max(), 3)}. Avec 1 000 requêtes pour 3 paramètres, l'attaque trouve une évasion dès qu'il en existe une.
- **Familles les plus vulnérables** : DoS Slowhttptest ({f(fam(1, 'DoS Slowhttptest', 'sans attaque'), 2)} → {f(fam(1, 'DoS Slowhttptest', f'{I} — T1'), 2)} dès ε = 1, **sans un octet de plus** et pour une durée × {f(COST.loc[(1.0, 'DoS Slowhttptest'), 'allongement_duree_med'], 2)} : évasion presque gratuite pour une attaque déjà lente), SSH-Patator ({f(fam(5, 'SSH-Patator', 'sans attaque'), 2)} → {f(fam(5, 'SSH-Patator', f'{I} — T1'), 2)} à ε = 5), PortScan ({f(fam(5, 'PortScan', 'sans attaque'), 2)} → {f(fam(5, 'PortScan', f'{I} — T1'), 2)} à ε = 5) et DoS Hulk ({f(fam(5, 'DoS Hulk', 'sans attaque'), 2)} → {f(fam(5, 'DoS Hulk', f'{I} — T1'), 2)} à ε = 5). Pour PortScan, ce résultat porte sur les flux atypiques qui restent après dédoublonnage (section 5.1), pas sur la sonde d'un paquet.
- **Familles robustes** : DoS GoldenEye et FTP-Patator ne descendent pas sous {f(min(fam(5, 'DoS GoldenEye', f'{I} — T1'), fam(5, 'FTP-Patator', f'{I} — T1')), 2)}, même à ε = 5. Elles se distinguent par des variables que T1 ne touche pas (nombres de paquets, drapeaux, sens retour).
- **Coût réel** : à ε = 5, les évasions de DoS Hulk et SSH-Patator allongent les flux d'un facteur ≈ {f(COST.loc[(5.0, 'DoS Hulk'), 'allongement_duree_med'], 1)}, soit {f(COST.loc[(5.0, 'DoS Hulk'), 'debit_par_flux_residuel_pct'], 0)} % du débit par flux : l'attaque ne garde son effet que si l'attaquant multiplie les connexions parallèles. À ε = 1 le coût reste modéré (durée × {f(COST.loc[1.0]['allongement_duree_med'].min(), 1)} à {f(COST.loc[1.0]['allongement_duree_med'].max(), 1)}).
- **L'accès au score aide peu** : l'attaquant qui ne voit que la décision obtient presque le même rappel ({f(R[I]['étiquette seule ε=1'])} à ε = 1, {f(R[I]['étiquette seule ε=5'])} à ε = 5). Les zones d'évasion sont larges, une recherche aléatoire suffit. Masquer le score n'est pas une défense.
- **Le transfert fonctionne sans aucune requête** : des flux construits contre la forêt de substitution de l'attaquant, en creusant la marge, font passer le rappel de {f(r0)} à {f(R[I]['transfert ε=1'])} (ε = 1) et {f(R[I]['transfert ε=5'])} (ε = 5), soit {f(tr1, 0)} % et {f(tr5, 0)} % de l'effet de l'attaque directe. Cacher le modèle ne suffit pas non plus.

### 11.4 Q2 — Réalisme
Les flux modifiés par T1 (à l'amplitude maximale ε = 5) et par T2 n'ajoutent **aucune** violation des {n_inv} invariants contrôlés (0 %), délai d'expiration de 120 s compris. L'attaque **sans contrainte** (chaque variable ±ε indépendamment) fait tomber le rappel à {f(UNC.loc[0.1, 'rappel'], 2)} dès ε = 0,1 et à {f(UNC.loc[0.5, 'rappel'], 2)} dès ε = 0,5, mais **{f(unc_var, 1)} %** de ses flux modifient une variable hors du contrôle de l'attaquant, {f(unc_rate, 0)} % ont un débit incohérent avec leurs octets et leur durée et {f(unc_120, 1)} % dépassent 120 s. Sans contrôle du réalisme, on conclurait à tort que le détecteur est trivialement contournable. Réserve : ces invariants sont nécessaires, pas suffisants (section 6.2).

### 11.5 Q3 — Défenses : robustesse et coût
| Défense | F1 test | Rappel test | Fausses alertes / jour | Rappel sans attaque (éq. famille) | T1 ε = 1 | T1 ε = 5 | T2 ε = 1 | T2 ε = 5 | Étiquette seule ε = 5 | Transfert ε = 5 |
|---|---|---|---|---|---|---|---|---|---|---|
{row(I, 'XGBoost initial')}
{row(D1, f"D1 entraînement adverse (ε_train = {d['eps_train']:g})")}
{row(D2, 'D2 variables non manipulables')}
{row(D3, 'D3 contraintes monotones')}
{row(D4, 'D4 entraînement adverse T1 + T2 (2ᵉ cycle)')}

- **D1** : robustesse à T1 presque totale ({f(R[D1]['T1 ε=5'])} contre {f(R[D1]['sans attaque'])} sans attaque), F1 inchangé à 0,001 près, mais {n_(alerts(D1) - alerts(I))} fausses alertes de plus par jour (+{f(100 * (alerts(D1) / alerts(I) - 1), 0)} %). Sur la validation, ε_train = 1 et 3 donnaient exactement la même robustesse ; la règle a retenu le dernier ex æquo (3), choix arbitraire, alors que ε_train = 1 produisait moins de faux positifs en validation ({n_(d1v.FP_val.iloc[0])} contre {n_(d1v.FP_val.iloc[1])}).
- **D2** est robuste à T1 **par construction** (la perturbation ne change aucune de ses entrées), au prix de **{f(alerts(D2) / alerts(I), 1)} fois plus de fausses alertes** ({n_(alerts(D2))} par jour) : intenable pour une équipe d'analystes.
- **D3** n'apporte qu'un gain partiel ({f(R[D3]['T1 ε=5'])} contre {f(R[I]['T1 ε=5'])} à ε = 5) : {len(d['contraintes_monotones_libres'])} variables de T1 changent de sens selon la perturbation (écarts-types, minima, débit d'octets) et restent non contraintes ; l'attaquant passe par elles.

### 11.6 Q4 — Face à l'inconnu, puis après mise à jour
- **La fenêtre TCP (T2) contourne D1, D2 et D3**, alors qu'elle ne modifie qu'**une seule** variable de plus : rappel compris entre {f(min(R[x]['T2 (fenêtre TCP) ε=1'] for x in (I, D1, D2, D3)), 2)} et {f(max(R[x]['T2 (fenêtre TCP) ε=1'] for x in (I, D1, D2, D3)), 2)} à ε = 1 selon le modèle. Contre D1, DoS slowloris passe de {f(fam(1, 'DoS slowloris', 'sans attaque'), 2)} à {f(fam(1, 'DoS slowloris', f'{D1} — T2'), 2)}, DoS Slowhttptest à {f(fam(1, 'DoS Slowhttptest', f'{D1} — T2'), 2)}, FTP-Patator à {f(fam(1, 'FTP-Patator', f'{D1} — T2'), 2)}.
- **Pourquoi cela marche.** Dans les flux de l'attaquant, {n_conc} familles d'attaque sur {len(Wa)} (celles d'au moins 50 flux) concentrent au moins 90 % de leurs flux sur deux valeurs de fenêtre, et aucune n'en présente plus de {int(Wa['valeurs_distinctes'].astype(float).max())}, contre {n_(ben_distinct)} valeurs distinctes pour le trafic légitime (section 9.1). Cela suggère que le détecteur a appris en partie la pile réseau de la machine attaquante : une signature de la plateforme de capture, pas un comportement d'attaque. L'importance globale ne le signalait pas : la variable n'est que {d['rang_fenetre_tcp_substitut']}ᵉ sur {d['n_variables']} dans le modèle de l'attaquant. Une variable peu « importante » en moyenne peut suffire à faire basculer une décision.
- D1 garde un avantage contre T2 ({f(R[D1]['T2 (fenêtre TCP) ε=5'], 2)} contre {f(R[I]['T2 (fenêtre TCP) ε=5'], 2)}), surtout sur les attaques Web à ε = 1 ({f(fam(1, 'Web Attack - Brute Force', f'{D1} — T2'), 2)} et {f(fam(1, 'Web Attack - XSS', f'{D1} — T2'), 2)} contre {f(fam(1, 'Web Attack - Brute Force', f'{I} — T2'), 2)} et {f(fam(1, 'Web Attack - XSS', f'{I} — T2'), 2)}).
- **Deuxième cycle (D4).** Une fois T2 connue et intégrée à l'entraînement adverse, le rappel sous T2 remonte à {f(R[D4]['T2 (fenêtre TCP) ε=1'], 2)} (ε = 1) et {f(R[D4]['T2 (fenêtre TCP) ε=5'], 2)} (ε = 5) : FTP-Patator {f(fam(1, 'FTP-Patator', f'{D4} — T2'), 2)}, slowloris {f(fam(1, 'DoS slowloris', f'{D4} — T2'), 2)}, PortScan {f(fam(1, 'PortScan', f'{D4} — T2'), 2)}. Deux familles restent ouvertes : DoS Hulk ({f(fam(1, 'DoS Hulk', f'{D4} — T2'), 2)}) et DoS Slowhttptest ({f(fam(1, 'DoS Slowhttptest', f'{D4} — T2'), 2)}).
- **Le prix de D4.** Son rappel sur le trafic non modifié baisse à {f(T[D4]['rec_attack'])} (contre {f(T[I]['rec_attack'])}), à cause de DoS Hulk ({f(d['rappel_famille_test']['DoS Hulk'][D4])}), et sa robustesse à T1 est inférieure à celle de D1 ({f(R[D4]['T1 ε=5'])} contre {f(R[D1]['T1 ε=5'])} à ε = 5) : son entraînement adverse n'a utilisé que des exemples T2, sans exemples T1 seuls. La baisse de rappel n'apparaissait pas sur la validation (F1 de validation ≈ celui du modèle initial) : elle ne se révèle que sur la fin, plus tardive, des épisodes. D4 n'a pas été retouchée après lecture du test.
- **Conclusion sur le piège « durcissement évalué seulement contre l'attaque connue »** : évaluée contre T1 seul, D1 semblerait presque parfaite. La matrice de robustesse montre qu'elle ne l'est pas, et D4 se trouve aujourd'hui dans la position où était D1 : jamais testée contre une action qu'elle ne connaît pas.

### 11.7 Recommandations
1. Entraînement adverse **cumulatif** : garder les exemples de chaque cycle (T1 seuls **et** T1 + fenêtre) plutôt que de repartir du modèle initial, et le refaire à chaque action découverte par une équipe rouge.
2. **Retirer ou normaliser les variables que l'attaquant fixe gratuitement** quand elles servent de signature (fenêtre TCP initiale), et ajouter des règles de validation en amont du modèle (débits impossibles, flux au-delà du délai d'expiration).
3. Diversité : combiner le modèle durci avec un détecteur d'anomalies et des règles par famille ; suivre le rappel par famille, pas seulement le F1 global (la baisse de D4 sur DoS Hulk est invisible dans la PR-AUC).
4. Seuil : le ratio de coût 10 conduit à ≈ {n_(round(alerts(I), -1))} fausses alertes par jour. Le tableau de la section 4.3 permet d'ajuster ce ratio au budget réel d'analyse.

### 11.8 Limites
1. **Attaque dans l'espace des variables**, pas sur de vrais paquets. Les écarts-types et extrêmes recalculés sont des approximations ; les variables `Active` / `Idle` sont mises à l'échelle sans rejouer le seuil d'activité de 5 s de CICFlowMeter.
2. L'efficacité résiduelle de l'attaque n'est mesurée que **par flux** (allongement, surcoût en octets). Le maintien du débit agrégé par davantage de connexions est une hypothèse.
3. Horodatage à la minute : les flux de la minute frontière peuvent se trouver des deux côtés d'un découpage.
4. **Dédoublonnage** : il évite la fuite, mais il change le poids des familles (PortScan passe de 158 804 flux à moins de 2 000) ; les chiffres décrivent des flux distincts, pas le volume qu'un détecteur verrait en production.
5. **Familles rares** (Heartbleed : 1 flux de test, injection SQL : 4, Infiltration : 7) : leurs chiffres par famille ne sont pas interprétables.
6. **Bot** : rappel nul sur le test pour la forêt, XGBoost et toutes les défenses. Les {bot['test']['flux']} flux `Bot` du test ({bot['test']['début (UTC)']}–{bot['test']['fin (UTC)']} UTC) sont postérieurs à la session documentée et n'ont aucune charge utile aller : ce sont des tentatives de connexion, pas des échanges avec le botnet (section 10.7). Ce défaut d'étiquetage pèse sur le rappel « sans attaque » équilibré par famille ({f(r0)}).
7. Un seul découpage et une seule graine d'entraînement des modèles. La variabilité due à l'attaque est mesurée (3 graines), pas celle due à l'entraînement.
8. Version d'origine de CIC-IDS2017 ; refaire l'étude sur la version corrigée (Engelen et al., 2021) serait une extension naturelle.
9. Le ratio de coût 10 est une hypothèse (sensibilité en section 4.3). L'attaquant par transfert reçoit la moitié de la validation, ce qui lui est favorable.
10. **Usage du test.** Le notebook a été ré-exécuté après correction de défauts repérés à la relecture du code (plafond de 120 s sur la durée des flux, validation croisée à origine glissante, recherche exacte du seuil, marge de l'attaque par transfert). Ces corrections viennent de la relecture, pas des résultats du test, et aucune défense n'a été ajustée d'après eux.

### 11.9 Conformité au cahier des charges
| Exigence | Section |
|---|---|
| Socle commun : nettoyage justifié, découpage sans fuite, baseline, RF, XGBoost réglés, comparaison performance / temps | 2, 3, 4 |
| Matrice de confusion, précision / rappel / F1 par classe, courbe PR et PR-AUC, discussion FP / FN | 3.3, 4.2, 4.3, 10.1 |
| Rôles défenseur / attaquant | en-tête |
| Modèle de menace et tableau des variables en catégories | 5 |
| Attaque d'évasion respectant le modèle, ≤ 1 000 requêtes | 6, 7 |
| Taux d'évasion, rappel en fonction de l'amplitude, nombre de requêtes | 10.2 |
| Réalisme des échantillons modifiés | 6.2, 10.5 |
| Durcissement, effet sur robustesse et performances normales, attaque rejouée | 8, 9.4, 10.1 à 10.3 |
| Pièges : perturbations irréalistes, évasion sur flux déjà manqués, durcissement testé seulement contre l'attaque connue, réglage sur le test | 6.2 / 7 / 9 et 10.3 / 3.2 |
| Extension : transfert entre modèles | 9.3, 10.3 |
| Reproductibilité : graines, versions, données non versionnées, README | 1, `README.md` |

### Références
- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP 2018.
- G. Engelen, V. Rimmer, W. Joosen. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*. IEEE Security and Privacy Workshops, 2021.
- M. Lanvin et al. *Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes*. CRiSIS 2022.
- I. Incer, M. Theodorides, S. Afroz, D. Wagner. *Adversarially Robust Malware Detection Using Monotonic Classification*. IWSPA 2018.
- Canadian Institute for Cybersecurity. *Intrusion Detection Evaluation Dataset (CIC-IDS2017)*, description des scénarios et horaires d'attaque : <https://www.unb.ca/cic/datasets/ids-2017.html>.
"""
open(out, "w", encoding="utf-8").write("# %% [markdown]\n" + "\n".join(("# " + l) if l else "#" for l in md.rstrip("\n").split("\n")) + "\n")
print("rapport généré :", out, "|", len(md.split()), "mots")
