# %% [markdown]
# ## 9. Au-delà du modèle de menace connu
# D1, D2 et D3 ont été conçues contre T1. L'attaquant essaie maintenant trois choses **qu'elles n'ont pas vues**. Tout ce qui suit est mis au point sur la **validation** ; l'évaluation sur le test a lieu une seule fois, en section 10.
#
# ### 9.1 Action inédite T2 : la fenêtre TCP initiale (attaquant)
# T2 = T1 + choix de `Init_Win_bytes_forward`. L'idée vient d'un raisonnement d'attaquant, pas d'un accès au détecteur : quelles variables du flux sont fixées par **ma** machine, sans coût et sans effet sur l'attaque ? La fenêtre TCP annoncée dans le SYN en fait partie, et T1 l'avait laissée de côté.
#
# L'attaquant entraîne aussi **son propre** modèle sur des flux CIC-IDS2017 qu'il possède (on lui donne la moitié de la validation, ce qui lui est favorable : même distribution que le détecteur). Ce modèle de substitution lui sert à situer la variable (tableau ci-dessous) et resservira pour l'attaque par transfert (9.3). Attention à la lecture : une importance globale ne dit pas si une variable permet l'évasion ; seule l'attaque le mesure.

# %%
T2_KW = dict(perturb_fn=perturb_t2, dim=4, free_dims=(3,))
surr_idx = np.random.default_rng(SEED + 7).choice(len(y_val), len(y_val) // 2, replace=False)
surrogate = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=SEED).fit(X_val[surr_idx], y_val[surr_idx])
tau_surr = choose_tau(y_val[surr_idx], proba_fn(surrogate)(X_val[surr_idx]))
print(f"Substitut entraîné sur {len(surr_idx):,} flux de l'attaquant ; seuil supposé par l'attaquant τ_s = {tau_surr:.3f}")
imp = pd.Series(surrogate.feature_importances_, index=FEATURES).sort_values(ascending=False)
imp_tab = pd.DataFrame({"importance (substitut)": imp.round(4), "catégorie": [CAT[c][0] for c in imp.index]}).head(10)
imp_tab.insert(0, "rang", range(1, len(imp_tab) + 1)); display(imp_tab)
WIN_RANK = list(imp.index).index(WIN_FEAT) + 1
print(f"Rang de {WIN_FEAT} dans le modèle de l'attaquant : {WIN_RANK} sur {len(imp)}")

# Valeurs de la fenêtre TCP initiale par famille, dans les flux que possède l'attaquant
def _top(s):
    v = s.value_counts(normalize=True).head(2)
    return " ; ".join(f"{int(a)} ({b:.0%})" for a, b in v.items())
win = pd.DataFrame({"famille": fam_val[surr_idx], "fenetre": X_val[surr_idx][:, FEAT_IDX[WIN_FEAT]]})
win_tab = win.groupby("famille")["fenetre"].agg(flux="size", valeurs_les_plus_frequentes=_top, valeurs_distinctes="nunique")
display(win_tab)

# %% [markdown]
# **Lecture.** Le tableau montre de combien de valeurs de fenêtre part chaque famille. Quand une famille se concentre sur une ou deux valeurs (celles de la pile réseau de la machine attaquante et de ses outils), un modèle peut apprendre « telle fenêtre + tel profil = attaque » : ce serait une signature de la plateforme de capture, pas un comportement d'attaque. Reste à mesurer si l'attaquant peut en sortir en changeant cette seule valeur.

# %%
rows = []
for nm, (m, tau) in DEFENDERS.items():
    t1, t2 = val_robustness(m, tau), val_robustness(m, tau, **T2_KW)
    rows.append({"défense": nm, "sans attaque": (proba_fn(m)(Xd) >= tau).mean(), "T1 ε=1": t1[1.0], "T1 ε=5": t1[5.0], "T2 ε=1": t2[1.0], "T2 ε=5": t2[5.0]})
t2_val = pd.DataFrame(rows).set_index("défense")
print("Rappel sous attaque sur les flux de développement de la VALIDATION (budget 300 requêtes) :"); display(t2_val.round(3))

# %% [markdown]
# ### 9.2 Attaquant qui ne voit que la décision
# Le détecteur ne renvoie que alerte / pas d'alerte. Sans score, l'escalade n'a plus de signal : l'attaque devient une recherche aléatoire pure dans la boîte T1, avec le même budget de 1 000 requêtes.
#
# ### 9.3 Attaque par transfert (aucune requête au détecteur)
# L'attaquant construit ses flux adverses contre son modèle de substitution (9.1), puis les rejoue **une seule fois** contre chaque défense. Contrairement à l'attaque directe, il ne s'arrête pas au premier passage sous le seuil du substitut : il utilise tout son budget pour **creuser la marge** (score le plus bas possible), car un flux qui passe de justesse sur le substitut se transfère mal.
