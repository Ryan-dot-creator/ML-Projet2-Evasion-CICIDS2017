# %% [markdown]
# ## 10. Évaluation finale sur le **test** (utilisé une seule fois)
# Tous les seuils, hyperparamètres, choix de défense et réglages d'attaque ont été fixés sur train / validation. Le test sert ici une seule fois.
#
# ### 10.1 Performances normales (sans attaque)
# Chaque modèle utilise **son** seuil choisi sur la validation (règle de coût de la section 4.3). Intervalles de confiance à 95 % par bootstrap (200 rééchantillonnages du test).

# %%
def bootstrap_ci(y, proba, tau, n_boot=200 if not QUICK else 30, seed=SEED):
    rng = np.random.default_rng(seed); pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0); vals = []
    for _ in range(n_boot):
        idx = np.concatenate([rng.choice(pos, len(pos)), rng.choice(neg, len(neg))])     # bootstrap stratifié
        yy, pp = y[idx], proba[idx]; pred = pp >= tau
        tp = (pred & (yy == 1)).sum(); fp = (pred & (yy == 0)).sum(); fn = (~pred & (yy == 1)).sum()
        vals.append((2 * tp / (2 * tp + fp + fn), tp / (tp + fn), average_precision_score(yy, pp)))
    lo, hi = np.percentile(vals, [2.5, 97.5], axis=0)
    return {"F1 IC95": f"[{lo[0]:.4f}, {hi[0]:.4f}]", "rappel IC95": f"[{lo[1]:.4f}, {hi[1]:.4f}]", "PR-AUC IC95": f"[{lo[2]:.4f}, {hi[2]:.4f}]"}

ALL_MODELS = {n: (m, choose_tau(y_val, proba_val[n])) for n, m in models.items() if n != DEF_NAME}
ALL_MODELS.update(DEFENDERS)
proba_test, rows_t, ci_rows = {}, {}, {}
for n, (m, tau) in ALL_MODELS.items():
    t0 = time.time(); proba_test[n] = proba_fn(m)(X_test); dt = (time.time() - t0) / len(X_test) * 1e6
    rows_t[n] = {**evaluate(y_test, proba_test[n], tau), "τ (validation)": tau, "inférence (µs/flux)": dt}
    if n in DEFENDERS or n == "Forêt aléatoire": ci_rows[n] = bootstrap_ci(y_test, proba_test[n], tau)
res_test = pd.DataFrame(rows_t).T
print(f"TEST — {len(y_test):,} flux, prévalence {y_test.mean():.4f}")
display(res_test[["τ (validation)", "prec_benign", "rec_benign", "f1_benign", "prec_attack", "rec_attack", "f1_attack", "f1_macro",
                  "pr_auc", "roc_auc", "FP", "FN", "FPR", "inférence (µs/flux)"]].round(4))
display(pd.DataFrame(ci_rows).T)
res_test["fausses alertes / jour (extrapolé)"] = res_test["FPR"] * BENIGN_PER_DAY
display(res_test[["FP", "FN", "fausses alertes / jour (extrapolé)"]].round(1))
fam_rec_test = pd.concat({n: family_recall(y_test, proba_test[n], ALL_MODELS[n][1], fam_test)["rappel"] for n in ALL_MODELS}, axis=1)
fam_rec_test.insert(0, "flux", family_recall(y_test, proba_test["XGBoost initial"], DEFENDERS["XGBoost initial"][1], fam_test)["flux"])
print("Rappel par famille sur le test :"); display(fam_rec_test.round(3))
fig, axs = plt.subplots(1, 3, figsize=(17, 4.2))
for n in ["Baseline LR", "Forêt aléatoire"] + list(DEFENDERS):
    pr, rc, _ = precision_recall_curve(y_test, proba_test[n]); axs[0].plot(rc, pr, label=f"{n} ({average_precision_score(y_test, proba_test[n]):.4f})")
axs[0].axhline(y_test.mean(), ls=":", c="grey", label="aléatoire"); axs[0].set(xlabel="Rappel", ylabel="Précision", title="Courbes PR (test)", ylim=(0, 1.02))
axs[0].legend(fontsize=7)
for ax, n in zip(axs[1:], ["XGBoost initial", "D1 entraînement adverse"]):
    ConfusionMatrixDisplay(confusion_matrix(y_test, (proba_test[n] >= ALL_MODELS[n][1]).astype(int)), display_labels=["Légitime", "Attaque"]).plot(ax=ax, colorbar=False, values_format="d")
    ax.set_title(f"{n} (test)", fontsize=10)
plt.tight_layout(); plt.savefig("fig_test_pr_confusion.png", dpi=150); plt.show()

# %% [markdown]
# ### 10.2 Attaque T1 contre chaque défense : rappel en fonction de l'amplitude
# Attaque **adaptative** : elle interroge directement le modèle visé (y compris les modèles durcis). Répétée avec plusieurs graines d'attaque (moyenne ± écart-type) ; intervalle de Wilson à 95 % sur les flux. En pointillés : l'attaque **sans contrainte** (chaque variable ±ε indépendamment) contre le modèle initial, pour montrer ce que l'on surestimerait sans contrôle du réalisme.

# %%
att_idx = sample_attack_flows(y_test, fam_test, CAP_FAMILY, SEED)
Xa_t, fam_a = X_test[att_idx], fam_test[att_idx]
print(f"{len(att_idx)} flux d'attaque de test attaqués, {len(np.unique(fam_a))} familles")
MODES = {"T1": dict(), "T2": dict(perturb_fn=perturb_t2, dim=4, free_dims=(3,)), "T1 étiquette seule": dict(hard_label=True),
         "sans contrainte": dict(perturb_fn=lambda X, th: (np.asarray(X, np.float64) * (1 + th)).astype(np.float32),
                                 dim=X_test.shape[1], symmetric=True, mut_prob=0.1)}
RUNS = {}
def run(def_name, mode, eps, seed):
    key = (def_name, mode, eps, seed)
    if key not in RUNS:
        m, tau = DEFENDERS[def_name]
        RUNS[key] = evasion_attack(proba_fn(m), Xa_t, eps, tau, seed=seed, **MODES[mode])
    return RUNS[key]

def summarize(def_name, mode, eps_list, seeds):
    rows = []
    for eps in eps_list:
        rs = [run(def_name, mode, eps, s) for s in seeds]
        rec = np.array([r["detected_after"].mean() for r in rs]); r0 = rs[0]
        lo, hi = wilson(r0["detected_after"].sum(), len(r0["detected_after"]))
        ev = np.array([r["success"][r["init_detected"]].mean() if r["init_detected"].any() else np.nan for r in rs])
        qs = np.concatenate([r["queries"][r["success"]] for r in rs])
        rows.append(dict(défense=def_name, attaque=mode, eps=eps, rappel=rec.mean(), rappel_std=rec.std(), ic_lo=lo, ic_hi=hi,
                         taux_evasion=ev.mean(), requetes_med=np.median(qs) if len(qs) else np.nan))
    return pd.DataFrame(rows)

t_all = time.time(); curves = {}
for dn in DEFENDERS:
    curves[dn] = summarize(dn, "T1", EPS_GRID, ATTACK_SEEDS); print(f"{dn:28s} T1 OK ({time.time()-t_all:.0f}s)")
curve_unc = summarize("XGBoost initial", "sans contrainte", EPS_GRID, ATTACK_SEEDS[:1]); print(f"sans contrainte OK ({time.time()-t_all:.0f}s)")
display(pd.concat(curves.values()).round(3))

fig, axs = plt.subplots(1, 3, figsize=(18, 4.5)); x = np.arange(len(EPS_GRID))
for (dn, c), mk in zip(curves.items(), ["o", "s", "D", "^", "v"]):
    axs[0].errorbar(x, c.rappel, yerr=c.rappel_std, marker=mk, capsize=3, label=dn); axs[0].fill_between(x, c.ic_lo, c.ic_hi, alpha=0.1)
    axs[1].plot(x, c.taux_evasion, marker=mk, label=dn); axs[2].plot(x, c.requetes_med, marker=mk, label=dn)
axs[0].plot(x, curve_unc.rappel, "k--", marker="x", label="XGBoost initial — attaque SANS contrainte")
axs[1].plot(x, curve_unc.taux_evasion, "k--", marker="x", label="sans contrainte")
for ax, t, yl in [(axs[0], "Rappel sous attaque T1 (moy. ± é.-t. graines, IC Wilson)", "Rappel"),
                  (axs[1], "Taux d'évasion (flux initialement détectés)", "Taux d'évasion"),
                  (axs[2], "Effort de l'attaquant", "Requêtes médianes jusqu'à l'évasion")]:
    ax.set_xticks(x); ax.set_xticklabels(EPS_GRID); ax.set(xlabel="Amplitude ε", ylabel=yl, title=t); ax.grid(alpha=.3)
axs[0].set_ylim(0, 1.02); axs[1].set_ylim(0, 1.02); axs[0].legend(fontsize=7); axs[2].set_yscale("log")
plt.tight_layout(); plt.savefig("fig_rappel_amplitude.png", dpi=150); plt.show()

# %% [markdown]
# ### 10.3 Matrice de robustesse : chaque défense face à chaque attaquant
# Rappel sous attaque (équilibré par famille) à ε = 1 et ε = 5. « Sans attaque » = rappel à ε = 0 sur les mêmes flux. Les colonnes T2, étiquette seule et transfert sont des attaques **que D1, D2 et D3 n'ont pas vues** ; D4 a été entraînée en connaissant T2.

# %%
EPS_MAT = [e for e in (1, 5) if e in EPS_GRID] or [EPS_GRID[-1]]
mat_rows, t_all = [], time.time()
transfer_X = {}
for eps in EPS_MAT:     # l'attaquant fabrique ses flux contre SON substitut, sans requête au vrai détecteur
    rs_ = evasion_attack(proba_fn(surrogate), Xa_t, eps, tau_surr, seed=SEED, stop_on_success=False)
    transfer_X[eps] = perturb(Xa_t, rs_["theta"])
print(f"transfert construit ({time.time()-t_all:.0f}s)")
for dn, (m, tau) in DEFENDERS.items():
    row = {"défense": dn, "sans attaque": run(dn, "T1", 0, ATTACK_SEEDS[0])["detected_after"].mean()}
    for eps in EPS_MAT:
        row[f"T1 ε={eps}"] = curves[dn].set_index("eps").loc[eps, "rappel"]
        row[f"T2 (fenêtre TCP) ε={eps}"] = np.mean([run(dn, "T2", eps, s)["detected_after"].mean() for s in ATTACK_SEEDS])
        row[f"étiquette seule ε={eps}"] = np.mean([run(dn, "T1 étiquette seule", eps, s)["detected_after"].mean() for s in ATTACK_SEEDS])
        row[f"transfert ε={eps}"] = (proba_fn(m)(transfer_X[eps]) >= tau).mean()
    mat_rows.append(row); print(f"{dn:28s} OK ({time.time()-t_all:.0f}s)")
robust = pd.DataFrame(mat_rows).set_index("défense")
robust.insert(0, "F1 test (normal)", [res_test.loc[d, "f1_attack"] for d in robust.index])
robust.insert(1, "fausses alertes / jour", [res_test.loc[d, "fausses alertes / jour (extrapolé)"] for d in robust.index])
display(robust.round(3))
fig, ax = plt.subplots(figsize=(13, 3.8))
mshow = robust.drop(columns=["F1 test (normal)", "fausses alertes / jour"])
im = ax.imshow(mshow.to_numpy(dtype=float), cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
ax.set_xticks(range(mshow.shape[1])); ax.set_xticklabels(mshow.columns, rotation=30, ha="right", fontsize=8)
ax.set_yticks(range(mshow.shape[0])); ax.set_yticklabels(mshow.index, fontsize=9)
for i in range(mshow.shape[0]):
    for j in range(mshow.shape[1]): ax.text(j, i, f"{mshow.iat[i, j]:.2f}", ha="center", va="center", fontsize=8)
ax.set_title("Rappel sous attaque (vert = robuste)"); plt.colorbar(im, ax=ax, fraction=0.02); plt.tight_layout(); plt.savefig("fig_matrice_robustesse.png", dpi=150); plt.show()

# %% [markdown]
# ### 10.4 Analyse par famille et coût réel pour l'attaquant

# %%
def fam_table(eps):
    out = {"flux": pd.Series(fam_a).value_counts()}
    out["sans attaque"] = pd.Series(run("XGBoost initial", "T1", 0, ATTACK_SEEDS[0])["detected_after"], index=fam_a).groupby(level=0).mean()
    for dn in DEFENDERS:
        out[f"{dn} — T1"] = pd.Series(run(dn, "T1", eps, ATTACK_SEEDS[0])["detected_after"], index=fam_a).groupby(level=0).mean()
    for dn in ["XGBoost initial", "D1 entraînement adverse", "D2 non manipulables", "D4 entraînement adverse T1+T2"]:
        out[f"{dn} — T2"] = pd.Series(run(dn, "T2", eps, ATTACK_SEEDS[0])["detected_after"], index=fam_a).groupby(level=0).mean()
    return pd.DataFrame(out).round(2)
for eps in EPS_MAT:
    print(f"=== Rappel par famille sous attaque, ε = {eps} (graine {ATTACK_SEEDS[0]}) ==="); display(fam_table(eps))

cost_rows = []
for eps in [e for e in EPS_GRID if e > 0]:
    r = run("XGBoost initial", "T1", eps, ATTACK_SEEDS[0]); s = r["success"]
    if s.any():
        ov, st_ = attack_cost(Xa_t[s], r["theta"][s])
        for f in np.unique(fam_a[s]):
            mf = fam_a[s] == f
            cost_rows.append(dict(eps=eps, famille=f, evasions=int(mf.sum()), surcout_octets_med_pct=np.median(ov[mf]),
                                  allongement_duree_med=np.median(st_[mf]), debit_par_flux_residuel_pct=100 / np.median(st_[mf])))
cost_df = pd.DataFrame(cost_rows)
print("Coût des évasions réussies contre le XGBoost initial (médianes par famille) :")
display(cost_df[cost_df.eps.isin(EPS_MAT)].round(2))

# %% [markdown]
# ### 10.5 Réalisme des flux modifiés sur le test

# %%
eps_r = EPS_MAT[0]
rep_t1 = realism_report(Xa_t, perturb(Xa_t, run("XGBoost initial", "T1", EPS_GRID[-1], ATTACK_SEEDS[0])["theta"]))
print(f"T1, ε = {EPS_GRID[-1]} (amplitude maximale), contre XGBoost initial :"); display(rep_t1)
rep_t2 = realism_report(Xa_t, perturb_t2(Xa_t, run("D1 entraînement adverse", "T2", eps_r, ATTACK_SEEDS[0])["theta"]), NONMOD_T2)
print(f"T2, ε = {eps_r}, contre D1 :"); display(rep_t2)
r_unc = run("XGBoost initial", "sans contrainte", eps_r, ATTACK_SEEDS[0])
rep_unc = realism_report(Xa_t, MODES["sans contrainte"]["perturb_fn"](Xa_t, r_unc["theta"]))
print(f"SANS contrainte, ε = {eps_r} :"); display(rep_unc)

# %% [markdown]
# ### 10.6 Vérification indépendante
# On reconstruit les flux adverses à partir des θ retenus et on les re-soumet au modèle : les décisions doivent être exactement celles annoncées par l'attaque.

# %%
n_chk = 0
for (dn, mode, eps, seed), r in RUNS.items():
    if mode in ("T1", "T2") and eps > 0:
        m, tau = DEFENDERS[dn]; pf = perturb if mode == "T1" else perturb_t2
        assert np.array_equal(proba_fn(m)(pf(Xa_t, r["theta"])) >= tau, r["detected_after"]), (dn, mode, eps, seed)
        n_chk += 1
print(f"Vérification OK sur {n_chk} exécutions d'attaque.")

# %% [markdown]
# ### 10.7 Analyse d'erreur : pourquoi la famille Bot n'est-elle pas détectée sur le test ?
# Analyse faite **après** l'évaluation finale ; elle n'a servi à aucun choix. On compare les flux étiquetés `Bot` des trois fenêtres chronologiques. La documentation du CIC situe la session du botnet Ares entre 10:02 et 11:02 heure locale, soit 13:02–14:02 UTC (les horodatages de ce miroir sont en UTC).

# %%
bot = df[df["Label"] == "Bot"]
def _bot_stats(g):
    Xg = g[FEATURES].to_numpy(np.float32)
    return pd.Series({"flux": len(g), "début (UTC)": g["Timestamp"].min().strftime("%H:%M"), "fin (UTC)": g["Timestamp"].max().strftime("%H:%M"),
                      "charge utile aller médiane (o)": g["Total Length of Fwd Packets"].median(),
                      "% sans charge utile aller": 100 * (g["Total Length of Fwd Packets"] == 0).mean(),
                      "octets retour médians": g["Total Length of Bwd Packets"].median(),
                      "durée médiane (s)": g["Flow Duration"].median() / 1e6,
                      "fenêtre TCP retour médiane": g["Init_Win_bytes_backward"].median(),
                      "% détectés (XGBoost initial)": 100 * (proba_fn(model_init)(Xg) >= DEFENDERS["XGBoost initial"][1]).mean()})
bot_tab = pd.concat({s: _bot_stats(bot[bot["split"] == s]) for s in ["train", "val", "test"]}, axis=1)
display(bot_tab)

# %% [markdown]
# **Lecture.** Les flux `Bot` du test commencent après la fin documentée de la session. Ils n'ont aucune charge utile dans le sens aller, durent environ une seconde et reçoivent une réponse minimale : ce profil est celui de **tentatives de connexion répétées vers un serveur de commande qui ne répond plus**, pas d'un échange avec le botnet. Le modèle a appris l'échange réel (train) et ne signale pas ces tentatives. Engelen et al. (2021) rangent ce type de flux dans une catégorie « tentative » et ne les comptent pas comme attaques. Le rappel nul sur Bot est donc d'abord un problème d'**étiquetage du jeu**, et il tire vers le bas le rappel « sans attaque » équilibré par famille.

# %%
def _tab(t): return json.loads(pd.DataFrame(t).to_json(orient="index", force_ascii=False))
summary = {"config": {k: (v if not isinstance(v, tuple) else list(v)) for k, v in CONFIG.items()}, "eps_train": EPS_TRAIN,
           "nettoyage": {k: int(v) for k, v in log.items()}, "n_variables": len(FEATURES), "n_flux_attaques": int(len(att_idx)),
           "hyperparametres": {k: {kk: (vv if not isinstance(vv, np.generic) else vv.item()) for kk, vv in v.items()} for k, v in best.items()},
           "seuils": {n: float(t) for n, (m, t) in ALL_MODELS.items()},
           "validation": _tab(res_val), "seuil_cout_validation": threshold_table(y_val, proba_val[DEF_NAME]).to_dict(orient="records"),
           "decoupage_aleatoire": _tab(cmp), "defenses_validation": cand_tab.to_dict(orient="records"), "t2_validation": _tab(t2_val),
           "rang_fenetre_tcp_substitut": int(WIN_RANK), "fenetre_par_famille": _tab(win_tab), "contraintes_monotones_libres": [c for c in FEATURES if direction[c] == 0 and FEAT_IDX[c] in T1_IDX],
           "test_normal": _tab(res_test), "test_ic95": ci_rows, "rappel_famille_test": _tab(fam_rec_test),
           "robustesse": _tab(robust), "courbes_T1": pd.concat(curves.values()).to_dict(orient="records"),
           "courbe_sans_contrainte": curve_unc.to_dict(orient="records"),
           "familles_sous_attaque": {str(e): _tab(fam_table(e)) for e in EPS_MAT}, "cout_attaquant": cost_df.to_dict(orient="records"),
           "realisme": {"T1": _tab(rep_t1), "T2": _tab(rep_t2), "sans_contrainte": _tab(rep_unc)}, "bot": _tab(bot_tab.T.astype(str))}
with open("resultats_projet2.json", "w") as f: json.dump(summary, f, indent=1, ensure_ascii=False, default=lambda o: o.item() if hasattr(o, "item") else str(o))
print("Résultats : resultats_projet2.json, fig_rappel_amplitude.png, fig_matrice_robustesse.png, fig_test_pr_confusion.png")
