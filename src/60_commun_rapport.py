# %% [markdown]
# ## 11. Rapport
#
# *Tous les chiffres de cette section sont lus dans `resultats_projet2.json`, produit par l'exécution ci-dessus (`QUICK = False`, `SEED = 42`). Rappel sous attaque = rappel équilibré par famille sur 1 112 flux d'attaque de test (100 par famille au plus).*
#
# ### 11.1 Résumé
# Un détecteur XGBoost à **F1 = 0,992** sur le test (découpage chronologique, sans fuite) perd **21 points de rappel** face à un attaquant réaliste qui ne fait que ralentir, remplir ou espacer son trafic (0,897 → 0,687 à ε = 5), sans violer aucun des invariants physiques contrôlés. L'entraînement adverse (D1) annule presque cet effet (0,886), pour 34 % de fausses alertes en plus. Mais une **quatrième action, gratuite et non anticipée** (choisir la fenêtre TCP initiale), fait tomber le rappel à **0,20** pour le modèle initial et à **0,51** pour D1. Un second cycle d'entraînement adverse qui intègre cette action (D4) remonte à **0,81**, mais perd 2,4 points de rappel sur le trafic non modifié. Une défense ne protège que contre le modèle de menace pour lequel elle a été construite, et chaque cycle a un coût.
#
# ### 11.2 Données, protocole et modèles
# - 2 830 743 flux → 2 195 583 après nettoyage ; **22 % de doublons exacts** supprimés avant le découpage (98,8 % des flux PortScan sont des doublons).
# - Découpage **chronologique par épisode** (60/20/20), validation croisée temporelle à origine glissante, seuil choisi par le coût (FN = 10 × FP) sur la validation, test utilisé pour les résultats finaux uniquement.
# - Test : baseline LR F1 = 0,851 (PR-AUC 0,907) ; arbre de profondeur 4 F1 = 0,855 ; forêt aléatoire F1 = 0,984 (IC 95 % [0,9837 ; 0,9849]) ; **XGBoost F1 = 0,992** (IC 95 % [0,9917 ; 0,9926]), PR-AUC 0,997 pour une prévalence de 0,153, 411 faux positifs et 646 faux négatifs sur 439 109 flux, soit **≈ 500 fausses alertes par jour** au volume réel. Inférence ≈ 3,7 µs par flux : compatible avec une détection quasi temps réel.
# - **Effet du protocole** : avec un découpage aléatoire, le même modèle manque 0,07 % des attaques contre 0,36 % en chronologique (5 fois moins), et le rappel de Bot y passe de 0,24 à 0,99. Les scores supérieurs à 99,9 % publiés sur ce jeu mesurent en partie de la mémorisation.
#
# ### 11.3 Q1 — Vulnérabilité à un attaquant réaliste (T1)
# | ε | 0 | 0,1 | 0,5 | 1 | 2 | 5 |
# |---|---|---|---|---|---|---|
# | Rappel sous attaque (XGBoost initial) | 0,897 | 0,831 | 0,807 | 0,788 | 0,750 | 0,687 |
# | Taux d'évasion (flux détectés au départ) | — | 7,4 % | 10,1 % | 12,2 % | 16,4 % | 23,4 % |
# | Requêtes médianes jusqu'à l'évasion | — | 2 | 3 | 4 | 3 | 9 |
#
# - Variabilité entre les 3 graines d'attaque : écart-type du rappel ≤ 0,004. Avec 1 000 requêtes pour 3 paramètres, l'attaque trouve une évasion dès qu'il en existe une.
# - **Familles les plus vulnérables** : DoS Slowhttptest (0,99 → 0,29 dès ε = 1, **sans un octet de plus** et pour une durée × 1,41 : évasion presque gratuite pour une attaque déjà lente), SSH-Patator (0,94 → 0,17 à ε = 5), PortScan (0,99 → 0,61 à ε = 5) et DoS Hulk (0,99 → 0,77 à ε = 5). Pour PortScan, ce résultat porte sur les flux atypiques qui restent après dédoublonnage (section 5.1), pas sur la sonde d'un paquet.
# - **Familles robustes** : DoS GoldenEye et FTP-Patator ne descendent pas sous 1,00, même à ε = 5. Elles se distinguent par des variables que T1 ne touche pas (nombres de paquets, drapeaux, sens retour).
# - **Coût réel** : à ε = 5, les évasions de DoS Hulk et SSH-Patator allongent les flux d'un facteur ≈ 7,5, soit 13 % du débit par flux : l'attaque ne garde son effet que si l'attaquant multiplie les connexions parallèles. À ε = 1 le coût reste modéré (durée × 1,4 à 2,9).
# - **L'accès au score aide peu** : l'attaquant qui ne voit que la décision obtient presque le même rappel (0,790 à ε = 1, 0,690 à ε = 5). Les zones d'évasion sont larges, une recherche aléatoire suffit. Masquer le score n'est pas une défense.
# - **Le transfert fonctionne sans aucune requête** : des flux construits contre la forêt de substitution de l'attaquant, en creusant la marge, font passer le rappel de 0,897 à 0,818 (ε = 1) et 0,814 (ε = 5), soit 72 % et 40 % de l'effet de l'attaque directe. Cacher le modèle ne suffit pas non plus.
#
# ### 11.4 Q2 — Réalisme
# Les flux modifiés par T1 (à l'amplitude maximale ε = 5) et par T2 n'ajoutent **aucune** violation des 13 invariants contrôlés (0 %), délai d'expiration de 120 s compris. L'attaque **sans contrainte** (chaque variable ±ε indépendamment) fait tomber le rappel à 0,20 dès ε = 0,1 et à 0,00 dès ε = 0,5, mais **89,8 %** de ses flux modifient une variable hors du contrôle de l'attaquant, 58 % ont un débit incohérent avec leurs octets et leur durée et 4,8 % dépassent 120 s. Sans contrôle du réalisme, on conclurait à tort que le détecteur est trivialement contournable. Réserve : ces invariants sont nécessaires, pas suffisants (section 6.2).
#
# ### 11.5 Q3 — Défenses : robustesse et coût
# | Défense | F1 test | Rappel test | Fausses alertes / jour | Rappel sans attaque (éq. famille) | T1 ε = 1 | T1 ε = 5 | T2 ε = 1 | T2 ε = 5 | Étiquette seule ε = 5 | Transfert ε = 5 |
# |---|---|---|---|---|---|---|---|---|---|---|
# | XGBoost initial | 0,992 | 0,990 | 502 | 0,897 | 0,788 | 0,687 | 0,287 | 0,204 | 0,690 | 0,814 |
# | D1 entraînement adverse (ε_train = 3) | 0,991 | 0,991 | 674 | 0,899 | 0,889 | 0,886 | 0,552 | 0,510 | 0,886 | 0,892 |
# | D2 variables non manipulables | 0,979 | 0,987 | 2 469 | 0,880 | 0,880 | 0,880 | 0,384 | 0,384 | 0,880 | 0,880 |
# | D3 contraintes monotones | 0,987 | 0,984 | 790 | 0,893 | 0,810 | 0,768 | 0,309 | 0,214 | 0,773 | 0,821 |
# | D4 entraînement adverse T1 + T2 (2ᵉ cycle) | 0,980 | 0,967 | 487 | 0,888 | 0,819 | 0,833 | 0,804 | 0,806 | 0,867 | 0,877 |
#
# - **D1** : robustesse à T1 presque totale (0,886 contre 0,899 sans attaque), F1 inchangé à 0,001 près, mais 171 fausses alertes de plus par jour (+34 %). Sur la validation, ε_train = 1 et 3 donnaient exactement la même robustesse ; la règle a retenu le dernier ex æquo (3), choix arbitraire, alors que ε_train = 1 produisait moins de faux positifs en validation (385 contre 505).
# - **D2** est robuste à T1 **par construction** (la perturbation ne change aucune de ses entrées), au prix de **4,9 fois plus de fausses alertes** (2 469 par jour) : intenable pour une équipe d'analystes.
# - **D3** n'apporte qu'un gain partiel (0,768 contre 0,687 à ε = 5) : 6 variables de T1 changent de sens selon la perturbation (écarts-types, minima, débit d'octets) et restent non contraintes ; l'attaquant passe par elles.
#
# ### 11.6 Q4 — Face à l'inconnu, puis après mise à jour
# - **La fenêtre TCP (T2) contourne D1, D2 et D3**, alors qu'elle ne modifie qu'**une seule** variable de plus : rappel compris entre 0,29 et 0,55 à ε = 1 selon le modèle. Contre D1, DoS slowloris passe de 0,99 à 0,12, DoS Slowhttptest à 0,19, FTP-Patator à 0,52.
# - **Pourquoi cela marche.** Dans les flux de l'attaquant, 9 familles d'attaque sur 11 (celles d'au moins 50 flux) concentrent au moins 90 % de leurs flux sur deux valeurs de fenêtre, et aucune n'en présente plus de 8, contre 4 309 valeurs distinctes pour le trafic légitime (section 9.1). Cela suggère que le détecteur a appris en partie la pile réseau de la machine attaquante : une signature de la plateforme de capture, pas un comportement d'attaque. L'importance globale ne le signalait pas : la variable n'est que 33ᵉ sur 61 dans le modèle de l'attaquant. Une variable peu « importante » en moyenne peut suffire à faire basculer une décision.
# - D1 garde un avantage contre T2 (0,51 contre 0,20), surtout sur les attaques Web à ε = 1 (0,94 et 0,92 contre 0,00 et 0,00).
# - **Deuxième cycle (D4).** Une fois T2 connue et intégrée à l'entraînement adverse, le rappel sous T2 remonte à 0,80 (ε = 1) et 0,81 (ε = 5) : FTP-Patator 0,99, slowloris 0,95, PortScan 0,94. Deux familles restent ouvertes : DoS Hulk (0,64) et DoS Slowhttptest (0,57).
# - **Le prix de D4.** Son rappel sur le trafic non modifié baisse à 0,967 (contre 0,990), à cause de DoS Hulk (0,947), et sa robustesse à T1 est inférieure à celle de D1 (0,833 contre 0,886 à ε = 5) : son entraînement adverse n'a utilisé que des exemples T2, sans exemples T1 seuls. La baisse de rappel n'apparaissait pas sur la validation (F1 de validation ≈ celui du modèle initial) : elle ne se révèle que sur la fin, plus tardive, des épisodes. D4 n'a pas été retouchée après lecture du test.
# - **Conclusion sur le piège « durcissement évalué seulement contre l'attaque connue »** : évaluée contre T1 seul, D1 semblerait presque parfaite. La matrice de robustesse montre qu'elle ne l'est pas, et D4 se trouve aujourd'hui dans la position où était D1 : jamais testée contre une action qu'elle ne connaît pas.
#
# ### 11.7 Recommandations
# 1. Entraînement adverse **cumulatif** : garder les exemples de chaque cycle (T1 seuls **et** T1 + fenêtre) plutôt que de repartir du modèle initial, et le refaire à chaque action découverte par une équipe rouge.
# 2. **Retirer ou normaliser les variables que l'attaquant fixe gratuitement** quand elles servent de signature (fenêtre TCP initiale), et ajouter des règles de validation en amont du modèle (débits impossibles, flux au-delà du délai d'expiration).
# 3. Diversité : combiner le modèle durci avec un détecteur d'anomalies et des règles par famille ; suivre le rappel par famille, pas seulement le F1 global (la baisse de D4 sur DoS Hulk est invisible dans la PR-AUC).
# 4. Seuil : le ratio de coût 10 conduit à ≈ 500 fausses alertes par jour. Le tableau de la section 4.3 permet d'ajuster ce ratio au budget réel d'analyse.
#
# ### 11.8 Limites
# 1. **Attaque dans l'espace des variables**, pas sur de vrais paquets. Les écarts-types et extrêmes recalculés sont des approximations ; les variables `Active` / `Idle` sont mises à l'échelle sans rejouer le seuil d'activité de 5 s de CICFlowMeter.
# 2. L'efficacité résiduelle de l'attaque n'est mesurée que **par flux** (allongement, surcoût en octets). Le maintien du débit agrégé par davantage de connexions est une hypothèse.
# 3. Horodatage à la minute : les flux de la minute frontière peuvent se trouver des deux côtés d'un découpage.
# 4. **Dédoublonnage** : il évite la fuite, mais il change le poids des familles (PortScan passe de 158 804 flux à moins de 2 000) ; les chiffres décrivent des flux distincts, pas le volume qu'un détecteur verrait en production.
# 5. **Familles rares** (Heartbleed : 1 flux de test, injection SQL : 4, Infiltration : 7) : leurs chiffres par famille ne sont pas interprétables.
# 6. **Bot** : rappel nul sur le test pour la forêt, XGBoost et toutes les défenses. Les 279 flux `Bot` du test (14:53–15:59 UTC) sont postérieurs à la session documentée et n'ont aucune charge utile aller : ce sont des tentatives de connexion, pas des échanges avec le botnet (section 10.7). Ce défaut d'étiquetage pèse sur le rappel « sans attaque » équilibré par famille (0,897).
# 7. Un seul découpage et une seule graine d'entraînement des modèles. La variabilité due à l'attaque est mesurée (3 graines), pas celle due à l'entraînement.
# 8. Version d'origine de CIC-IDS2017 ; refaire l'étude sur la version corrigée (Engelen et al., 2021) serait une extension naturelle.
# 9. Le ratio de coût 10 est une hypothèse (sensibilité en section 4.3). L'attaquant par transfert reçoit la moitié de la validation, ce qui lui est favorable.
# 10. **Usage du test.** Le notebook a été ré-exécuté après correction de défauts repérés à la relecture du code (plafond de 120 s sur la durée des flux, validation croisée à origine glissante, recherche exacte du seuil, marge de l'attaque par transfert). Ces corrections viennent de la relecture, pas des résultats du test, et aucune défense n'a été ajustée d'après eux.
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
# | Durcissement, effet sur robustesse et performances normales, attaque rejouée | 8, 9.4, 10.1 à 10.3 |
# | Pièges : perturbations irréalistes, évasion sur flux déjà manqués, durcissement testé seulement contre l'attaque connue, réglage sur le test | 6.2 / 7 / 9 et 10.3 / 3.2 |
# | Extension : transfert entre modèles | 9.3, 10.3 |
# | Reproductibilité : graines, versions, données non versionnées, README | 1, `README.md` |
#
# ### Références
# - I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP 2018.
# - G. Engelen, V. Rimmer, W. Joosen. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*. IEEE Security and Privacy Workshops, 2021.
# - M. Lanvin et al. *Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes*. CRiSIS 2022.
# - I. Incer, M. Theodorides, S. Afroz, D. Wagner. *Adversarially Robust Malware Detection Using Monotonic Classification*. IWSPA 2018.
# - Canadian Institute for Cybersecurity. *Intrusion Detection Evaluation Dataset (CIC-IDS2017)*, description des scénarios et horaires d'attaque : <https://www.unb.ca/cic/datasets/ids-2017.html>.
