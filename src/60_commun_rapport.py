# %% [markdown]
# ## 11. Rapport
#
# *Tous les chiffres viennent de l'exécution ci-dessus (`QUICK = False`, `SEED = 42`) et sont enregistrés dans `resultats_projet2.json`. Rappel sous attaque = rappel équilibré par famille sur 1 112 flux d'attaque de test (100 par famille au plus).*
#
# ### 11.1 Résumé
# Un détecteur XGBoost à **F1 = 0,992** sur le test (découpage chronologique, sans fuite) perd **18 points de rappel** face à un attaquant réaliste qui ne fait que ralentir, remplir ou espacer son trafic (0,897 → 0,719 à ε = 5). L'entraînement adverse (D1) annule presque cet effet sans aucun coût sur les performances normales (0,885 à ε = 5). Mais une **quatrième action, gratuite et non anticipée** (choisir la fenêtre TCP initiale), fait tomber le rappel à **0,21** pour le modèle initial et à **0,48** pour le meilleur modèle durci : chaque défense ne protège que contre le modèle de menace pour lequel elle a été construite.
#
# ### 11.2 Données, protocole et modèles
# - 2 830 743 flux → 2 195 583 après nettoyage ; **22 % de doublons exacts** supprimés avant le découpage (98,8 % des flux PortScan sont des doublons).
# - Découpage **chronologique par épisode** (60/20/20), validation croisée temporelle par blocs, seuil choisi par le coût (FN = 10 × FP) sur la validation, test utilisé une fois.
# - Test : baseline LR F1 = 0,851 (PR-AUC 0,907) ; arbre profondeur 4 F1 = 0,855 ; forêt aléatoire F1 = 0,985 (IC 95 % [0,985 ; 0,986]) ; **XGBoost F1 = 0,992** (IC 95 % [0,991 ; 0,992]), PR-AUC 0,997 pour une prévalence de 0,153, 473 faux positifs pour 371 918 flux légitimes, soit **≈ 580 fausses alertes par jour** au volume réel. Inférence ≈ 4 µs par flux : compatible temps réel.
# - **Effet du protocole** : à volume d'entraînement égal, un découpage aléatoire manque 0,04 % des attaques contre 0,36 % en chronologique (9 fois moins), et le rappel de Bot y passe de 0,24 à 0,99. Les scores > 99,9 % publiés sur ce jeu mesurent en partie de la mémorisation.
#
# ### 11.3 Q1 — Vulnérabilité à un attaquant réaliste (T1)
# | ε | 0 | 0,1 | 0,5 | 1 | 2 | 5 |
# |---|---|---|---|---|---|---|
# | Rappel sous attaque (XGBoost initial) | 0,897 | 0,831 | 0,812 | 0,797 | 0,778 | 0,719 |
# | Taux d'évasion (flux détectés) | — | 7,4 % | 9,5 % | 11,2 % | 13,3 % | 19,8 % |
# | Requêtes médianes jusqu'à l'évasion | — | 2 | 5 | 6 | 8 | 24,5 |
#
# - Variabilité entre les 3 graines d'attaque : écart-type ≤ 0,001.
# - **Familles les plus vulnérables** : DoS Slowhttptest (0,99 → 0,29 dès ε = 1, **sans un octet de plus** et une durée × 1,38 : évasion quasi gratuite pour une attaque déjà lente), DoS Hulk (0,99 → 0,77 à ε = 5), PortScan (0,99 → 0,62 à ε = 5), SSH-Patator (0,94 → 0,39 à ε = 5).
# - **Familles robustes** : DoS GoldenEye, slowloris et FTP-Patator restent à 0,99–1,00. Elles se distinguent par des variables que T1 ne touche pas (nombres de paquets, drapeaux, sens retour).
# - **Coût réel** : à ε = 5, les évasions de DoS Hulk et SSH-Patator allongent les flux d'un facteur ≈ 7,3, soit 14 % du débit par flux. L'attaque n'est conservée que si l'attaquant multiplie les connexions parallèles. À ε = 1, le coût reste modéré (durée × 1,4 à 2,7).
# - **L'accès au score aide peu** : l'attaquant qui ne voit que la décision obtient le même rappel (0,798 à ε = 1, 0,734 à ε = 5). Les zones d'évasion sont larges, une recherche aléatoire suffit.
# - **Le transfert fonctionne mal** : des flux construits contre une forêt aléatoire de substitution ne font baisser le rappel que de 1,5 point (0,882 à ε = 5). Cacher le modèle n'est pas une défense, mais l'interroger reste nettement plus efficace.
#
# ### 11.4 Q2 — Réalisme
# Les flux modifiés par T1 et T2 n'ajoutent **aucune** violation des 12 invariants physiques (0 %). L'attaque **sans contrainte** (chaque variable ±ε indépendamment) fait tomber le rappel à 0,25 dès ε = 0,1 et à 0 dès ε = 0,5, mais **89,8 %** de ses flux modifient une variable hors du contrôle de l'attaquant et 58 % ont un débit incohérent avec leurs octets et leur durée. Sans contrôle du réalisme, on conclurait à tort que le détecteur est trivialement contournable.
#
# ### 11.5 Q3 — Défenses : robustesse et coût
# | Défense | F1 test | Fausses alertes / jour | Rappel sans attaque | T1 ε = 1 | T1 ε = 5 | T2 ε = 1 | T2 ε = 5 | Étiquette seule ε = 5 | Transfert ε = 5 |
# |---|---|---|---|---|---|---|---|---|---|
# | XGBoost initial | 0,992 | 578 | 0,897 | 0,797 | 0,719 | 0,302 | 0,214 | 0,734 | 0,882 |
# | D1 entraînement adverse (ε_train = 3) | 0,992 | 584 | 0,898 | **0,889** | **0,885** | **0,502** | **0,478** | **0,885** | 0,892 |
# | D2 variables non manipulables | 0,979 | 2 316 | 0,879 | 0,879 | 0,879 | 0,335 | 0,335 | 0,879 | 0,879 |
# | D3 contraintes monotones | 0,987 | 868 | 0,894 | 0,814 | 0,776 | 0,323 | 0,222 | 0,803 | 0,889 |
#
# - **D1** est le meilleur compromis : robustesse à T1 presque totale (0,885 contre 0,898 sans attaque), aucune perte de F1, + 6 fausses alertes par jour. Sur la validation, ε_train = 1 et 3 donnaient la même robustesse ; la règle de sélection a retenu 3.
# - **D2** est robuste à T1 **par construction** (la perturbation ne change aucune de ses entrées), mais au prix de **4 fois plus de fausses alertes** (2 316 par jour) : intenable pour une équipe d'analystes.
# - **D3** n'apporte qu'un gain partiel (0,776 contre 0,719 à ε = 5) : 6 variables T1 changent de sens selon la perturbation (écarts-types, minima, débit d'octets) et restent non contraintes, l'attaquant passe par elles.
#
# ### 11.6 Q4 — Face à l'inconnu
# - **La fenêtre TCP (T2) casse toutes les défenses**, y compris D2, alors qu'elle ne modifie qu'**une seule** variable. FTP-Patator passe de 1,00 à 0,02 contre D1, slowloris de 0,99 à 0,07. Le détecteur s'appuie donc fortement sur une valeur que l'attaquant fixe gratuitement dans son SYN. C'est plus probablement une signature des outils et de la plateforme de capture qu'un comportement d'attaque (à confirmer par une analyse d'importance, cf. projet 1).
# - D1 garde un avantage contre T2 (0,48 contre 0,21), surtout sur les attaques Web à ε = 1 (0,92–0,94 contre 0,08–0,13) : les flux adverses d'entraînement ont appris au modèle à ne pas dépendre que des variables temporelles et de taille.
# - **Conclusion sur le piège « durcissement évalué seulement contre l'attaque connue »** : évaluée contre T1 seul, D1 semblerait presque parfaite. La matrice de robustesse montre qu'elle ne l'est pas.
#
# ### 11.7 Recommandations
# 1. Ré-entraînement adverse **avec toutes les actions gratuites connues** (T1 + fenêtre TCP), refait à chaque nouvelle action découverte par une équipe rouge.
# 2. **Règles de validation** en amont du modèle : cohérence de la fenêtre TCP initiale avec le système déclaré, débits impossibles, et retrait des variables triviales à forger quand elles dominent les décisions.
# 3. Diversité : combiner le modèle durci avec un détecteur d'anomalies et des règles par famille ; suivre le taux d'alerte par famille en production.
# 4. Seuil : le ratio de coût 10 conduit à ≈ 580 fausses alertes par jour. Le tableau de la section 4.3 permet d'ajuster ce ratio au budget réel d'analyse.
#
# ### 11.8 Limites
# 1. **Attaque dans l'espace des variables**, pas sur de vrais paquets. Les formules de recalcul (écarts-types, extrêmes) sont approchées, et les variables `Active` / `Idle` ne réagissent pas à la pause insérée.
# 2. L'efficacité résiduelle de l'attaque n'est mesurée que **par flux** (allongement, surcoût en octets). Le maintien du débit agrégé par plus de connexions est une hypothèse.
# 3. Horodatage à la minute : les flux de la minute frontière peuvent se trouver des deux côtés d'un découpage.
# 4. **Familles rares** (Heartbleed : 1 flux de test, injection SQL : 4, Infiltration : 7) : leurs chiffres par famille ne sont pas interprétables.
# 5. **Bot** : rappel nul sur le test pour tous les modèles complexes (0,24 en validation). La fin de l'épisode (14:53–15:59) diffère de son début, et l'étiquetage de Bot fait partie des défauts documentés du jeu (Engelen et al., 2021). Ce point pèse sur le rappel « sans attaque » équilibré par famille (0,897).
# 6. Un seul découpage et une seule graine d'entraînement des défenses. La variabilité due à l'attaque est mesurée (3 graines), pas celle due à l'entraînement.
# 7. Version d'origine de CIC-IDS2017 ; refaire l'étude sur la version corrigée (Engelen et al., 2021) serait une extension naturelle.
# 8. Le ratio de coût 10 est une hypothèse (sensibilité en section 4.3). L'attaquant par transfert reçoit la moitié de la validation, ce qui lui est favorable.
#
# ### 11.9 Conformité au cahier des charges
# | Exigence | Section |
# |---|---|
# | Socle commun : nettoyage justifié, découpage sans fuite, baseline, RF, XGBoost réglés, comparaison performance / temps | 2, 3, 4 |
# | Matrice de confusion, précision / rappel / F1 par classe, courbe PR et PR-AUC, discussion FP / FN | 3.3, 4.2, 4.3, 10.1 |
# | Rôles défenseur / attaquant | en-tête |
# | Modèle de menace et tableau des variables en catégories | 5 |
# | Attaque d'évasion respectant le modèle, ≤ 1 000 requêtes | 6, 7 |
# | Taux d'évasion, rappel en fonction de l'amplitude, nombre de requêtes | 10.2 |
# | Réalisme des échantillons modifiés | 6.2, 10.5 |
# | Durcissement, effet sur robustesse et performances normales, attaque rejouée | 8, 10.1, 10.2, 10.3 |
# | Pièges : perturbations irréalistes, évasion sur flux déjà manqués, durcissement testé seulement contre l'attaque connue, réglage sur le test | 6.2 / 7 / 9 et 10.3 / 3.2 |
# | Extension : transfert entre modèles | 9, 10.3 |
# | Reproductibilité : graines, versions, données non versionnées, README | 1, `README.md` |
#
# ### Références
# - I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP 2018.
# - G. Engelen, V. Rimmer, W. Joosen. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*. IEEE Security and Privacy Workshops, 2021.
# - M. Lanvin et al. *Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes*. CRiSIS 2022.
# - I. Incer, M. Theodorides, S. Afroz, D. Wagner. *Adversarially Robust Malware Detection Using Monotonic Classification*. IWSPA 2018.
