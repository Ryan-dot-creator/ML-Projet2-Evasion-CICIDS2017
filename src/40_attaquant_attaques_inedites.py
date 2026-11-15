# %% [markdown]
# ## 9. Au-delà du modèle de menace connu (attaquant)
# Trois attaques que les défenses **n'ont pas vues** pendant leur conception, toutes évaluées une seule fois sur le test en section 10 :
# 1. **Action inédite (T2)** : T1 + choix de la fenêtre TCP initiale.
# 2. **Étiquette seule** : l'attaquant ne voit que alerte / pas d'alerte (pas de score) — recherche aléatoire pure, même budget.
# 3. **Transfert** : l'attaquant ne peut pas interroger le détecteur. Il entraîne sa propre forêt aléatoire sur ses propres données (des flux CIC-IDS2017 qu'il possède : on lui donne la moitié de la validation, ce qui est **favorable** à l'attaquant puisque même distribution), construit ses flux adverses contre elle, puis les rejoue **une seule fois** contre chaque défense.

# %%
surr_idx = np.random.default_rng(SEED + 7).choice(len(y_val), len(y_val) // 2, replace=False)
surrogate = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=SEED).fit(X_val[surr_idx], y_val[surr_idx])
tau_surr = choose_tau(y_val[surr_idx], proba_fn(surrogate)(X_val[surr_idx]))
print(f"Substitut entraîné sur {len(surr_idx):,} flux de l'attaquant ; seuil supposé par l'attaquant τ_s = {tau_surr:.3f}")
