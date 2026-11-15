# %% [markdown]
# ## 5. Modèle de menace (attaquant)
#
# **Ce que l'attaquant veut.** Qu'un flux réellement malveillant soit classé « légitime » (score < τ du détecteur) **sans détruire l'attaque**.
#
# **Ce que l'attaquant sait (boîte noire).** Le *format* des variables de flux (CICFlowMeter est public) et le **score** renvoyé par le détecteur pour un flux soumis, au plus 1 000 requêtes par flux. Il ne connaît ni les paramètres, ni les données d'entraînement, ni le seuil exact (il observe seulement s'il passe). Deux variantes plus faibles sont testées en section 9 : l'attaquant qui ne voit **que la décision** (alerte / pas d'alerte), et l'attaquant qui **ne peut pas interroger** le détecteur (transfert depuis un modèle de substitution).
#
# **Ce que l'attaquant peut faire — modèle de menace T1 (connu du défenseur).** Trois actions sur son propre trafic, d'amplitude bornée par ε ≥ 0 :
#
# | Action | Paramètre θ ∈ [0, ε] | Effet réel | Coût pour l'attaquant |
# |---|---|---|---|
# | **Ralentir** (dilatation du temps) | durée × (1 + θ₁) | tous les intervalles, durées actives/inactives étirés ; débits divisés | gratuit en octets ; moins de débit **par flux** |
# | **Remplir** (padding) | + θ₂ × max(taille moyenne des charges, 50) octets par paquet aller **portant déjà des données**, plafonné au MTU (1 460 o) | tailles de paquets, longueurs totales, statistiques de taille | bande passante supplémentaire |
# | **Insérer une pause** | + θ₃ × (plus grand intervalle aller) dans cet intervalle | durée, intervalles max / moyen / écart-type | gratuit ; exige au moins 2 paquets aller |
#
# Les variables dérivées (débits, moyennes, écarts-types, extrêmes) sont **recalculées de façon cohérente** par `perturb` : l'attaquant choisit 3 actions de trafic, pas 59 valeurs indépendantes. Tout ce qui exigerait de changer la nature de l'attaque ou dépend de la cible (nombres de paquets, drapeaux TCP, sens retour, protocole, fenêtre TCP du serveur…) est **non modifiable** dans T1.
#
# **Modèle de menace T2 (inconnu du défenseur, section 9.1).** T1 + une quatrième action réaliste : **choisir la fenêtre TCP initiale** annoncée dans son SYN (`Init_Win_bytes_forward`, réglable par `SO_RCVBUF` ou une pile réseau brute, entre 0 et 65 535 sans option d'échelle). T1 l'excluait volontairement : c'est ce qui permet de tester si une défense tient face à ce qu'elle n'a **pas anticipé** (piège « durcissement évalué seulement contre l'attaque connue »).
#
# ### 5.1 Plausibilité par famille : l'attaque garde-t-elle son effet ?
# | Famille | Ralentir | Remplir | Commentaire |
# |---|---|---|---|
# | DoS Hulk, GoldenEye, DDoS (inondations HTTP) | oui, **si** l'attaquant ouvre plus de connexions en parallèle : le détecteur raisonne flux par flux, le débit agrégé peut être conservé | oui (augmente même le volume) | coût réel : plus de sockets / de machines (bots) |
# | slowloris, Slowhttptest | oui : ces attaques **exploitent** la lenteur | oui (en-têtes HTTP) | limite : délais d'expiration du serveur |
# | FTP-/SSH-Patator (force brute) | oui, coût linéaire en essais par seconde (compensable par plus de flux) | SSH : oui (remplissage aléatoire prévu par le protocole, RFC 4253) ; FTP : limité | |
# | PortScan | peu utile : flux de 1 à 2 paquets | non (pas de charge utile) ; pause impossible (< 2 paquets aller) | robustesse attendue par construction |
# | Bot (Ares), attaques Web | oui (balises C2 plus espacées = plus discrètes) | oui (en-têtes, paramètres) | |
#
# Le coût réel (allongement de durée, surcoût en octets) de chaque évasion réussie est mesuré par famille en section 10.4.

# %%
TIME_FEATS = ['Flow Duration','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min','Fwd IAT Total','Fwd IAT Mean',
              'Fwd IAT Std','Fwd IAT Max','Fwd IAT Min','Bwd IAT Total','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min',
              'Active Mean','Active Std','Active Max','Active Min','Idle Mean','Idle Std','Idle Max','Idle Min']
RATE_FEATS = ['Flow Bytes/s','Flow Packets/s','Fwd Packets/s','Bwd Packets/s','Fwd Avg Bulk Rate','Bwd Avg Bulk Rate']
SIZE_FEATS = ['Total Length of Fwd Packets','Fwd Packet Length Max','Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std',
              'Avg Fwd Segment Size','Subflow Fwd Bytes','Packet Length Mean','Packet Length Std','Packet Length Variance',
              'Average Packet Size','Max Packet Length','Min Packet Length']
WIN_FEAT = 'Init_Win_bytes_forward'
CAT = {}
for c in FEATURES:
    if c in TIME_FEATS:   CAT[c] = ("T1 — libre", "ralentir / pause" + (" (effet indirect)" if c.startswith(("Bwd", "Active", "Idle")) else ""))
    elif c in SIZE_FEATS: CAT[c] = ("T1 — avec coût", "padding (bande passante)")
    elif c in RATE_FEATS: CAT[c] = ("T1 — dérivée (recalculée)", "débit = octets ou paquets / durée")
    elif c == WIN_FEAT:   CAT[c] = ("T2 seulement — libre", "fenêtre TCP du SYN (action inédite, section 9)")
    else:                 CAT[c] = ("Non modifiable", "-")
threat_table = pd.DataFrame(CAT, index=["Catégorie", "Mécanisme"]).T
display(threat_table["Catégorie"].value_counts().to_frame("variables"))
display(threat_table.sort_values(["Catégorie", "Mécanisme"]))
T1_IDX = [FEAT_IDX[c] for c in FEATURES if CAT[c][0].startswith("T1")]
NONMOD_T1 = [FEAT_IDX[c] for c in FEATURES if not CAT[c][0].startswith("T1")]
NONMOD_T2 = [j for j in NONMOD_T1 if FEATURES[j] != WIN_FEAT]

# %% [markdown]
# ## 6. Perturbations cohérentes et contrôle de réalisme
# ### 6.1 `perturb` (T1) et `perturb_t2` (T1 + fenêtre TCP)

# %%
MTU_PAYLOAD = 1460
def _g(X, name):
    j = FEAT_IDX.get(name)
    return X[:, j].astype(np.float64) if j is not None else np.zeros(len(X))
def _p(X, name, v):
    j = FEAT_IDX.get(name)
    if j is not None: X[:, j] = v
def _div(a, b, default=0.0):
    out = np.full(np.broadcast(a, b).shape, default, dtype=np.float64)
    np.divide(a, b, out=out, where=(b != 0)); return out
def _shift_var(var, m, mS, w, b):
    """Variance d'un ensemble dont une fraction w (de moyenne mS) est décalée de +b ; m = moyenne avant."""
    return np.maximum(0.0, var + 2*b*w*(mS - m) + b*b*w*(1 - w))
def _iat_stats(mean, std, tot_extra, g, n):
    """Moyenne / écart-type d'une série de n intervalles dont l'un (valant g) augmente de tot_extra."""
    mean2 = mean + tot_extra / n
    var2 = std**2 + mean**2 + (2*g*tot_extra + tot_extra**2) / n - mean2**2
    return mean2, np.sqrt(np.maximum(var2, 0.0))

def perturb(X0, theta):
    """T1 : theta[:, 0:3] = (ralentir, remplir, pause). Recalcule de façon cohérente toutes les variables affectées."""
    X0 = np.asarray(X0, dtype=np.float64); X = X0.copy()
    th_d, th_p, th_j = theta[:, 0], theta[:, 1], theta[:, 2]
    nf, nb = _g(X0, 'Total Fwd Packets'), _g(X0, 'Total Backward Packets'); N = nf + nb
    tf, tb = _g(X0, 'Total Length of Fwd Packets'), _g(X0, 'Total Length of Bwd Packets')
    dur0 = _g(X0, 'Flow Duration')
    # 1. padding : octets ajoutés aux seuls paquets aller qui portent déjà des données
    npay = np.minimum(_g(X0, 'act_data_pkt_fwd') if 'act_data_pkt_fwd' in FEAT_IDX else nf, nf)
    fmax, fmin, fmean, fstd = (_g(X0, 'Fwd Packet Length Max'), _g(X0, 'Fwd Packet Length Min'),
                               _g(X0, 'Fwd Packet Length Mean'), _g(X0, 'Fwd Packet Length Std'))
    m_pay = _div(tf, npay)
    b = np.floor(th_p * np.maximum(m_pay, 50.0))
    b = np.minimum(b, np.maximum(0.0, MTU_PAYLOAD - fmax))
    b = np.where(npay > 0, b, 0.0)
    add, padded = b * npay, b > 0
    _p(X, 'Total Length of Fwd Packets', tf + add)
    _p(X, 'Fwd Packet Length Max', fmax + b)
    _p(X, 'Fwd Packet Length Min', np.where((npay >= nf) & (nf > 0), fmin + b, fmin))
    _p(X, 'Fwd Packet Length Mean', fmean + _div(add, nf))
    _p(X, 'Fwd Packet Length Std', np.where(padded, np.sqrt(_shift_var(fstd**2, fmean, m_pay, _div(npay, nf), b)), fstd))
    pm, pv, ps = _g(X0, 'Packet Length Mean'), _g(X0, 'Packet Length Variance'), _g(X0, 'Packet Length Std')
    w = _div(npay, N)
    _p(X, 'Packet Length Mean', pm + b * w)
    _p(X, 'Average Packet Size', _g(X0, 'Average Packet Size') + _div(add, N))
    _p(X, 'Packet Length Variance', np.where(padded, _shift_var(pv, pm, m_pay, w, b), pv))
    _p(X, 'Packet Length Std', np.where(padded, np.sqrt(_shift_var(ps**2, pm, m_pay, w, b)), ps))
    _p(X, 'Max Packet Length', np.where(padded, np.maximum(_g(X0, 'Max Packet Length'), fmax + b), _g(X0, 'Max Packet Length')))
    pmin = _g(X0, 'Min Packet Length')
    _p(X, 'Min Packet Length', np.where(padded & (npay >= N), pmin + b, pmin))
    # 2. pause : le plus grand intervalle aller est allongé de delta
    fi_tot, fi_max, fi_mean, fi_std = (_g(X0, 'Fwd IAT Total'), _g(X0, 'Fwd IAT Max'), _g(X0, 'Fwd IAT Mean'), _g(X0, 'Fwd IAT Std'))
    i_max, i_mean, i_std = _g(X0, 'Flow IAT Max'), _g(X0, 'Flow IAT Mean'), _g(X0, 'Flow IAT Std')
    delta = np.where(nf >= 2, th_j * fi_max, 0.0); paused = delta > 0
    m2, s2 = _iat_stats(i_mean, i_std, delta, fi_max, np.maximum(N - 1, 1))
    fm2, fs2 = _iat_stats(fi_mean, fi_std, delta, fi_max, np.maximum(nf - 1, 1))
    _p(X, 'Flow Duration', dur0 + delta)
    _p(X, 'Flow IAT Max', np.where(paused, np.maximum(i_max, fi_max + delta), i_max))
    _p(X, 'Flow IAT Mean', np.where(paused, m2, i_mean));  _p(X, 'Flow IAT Std', np.where(paused, s2, i_std))
    _p(X, 'Fwd IAT Total', fi_tot + delta);                _p(X, 'Fwd IAT Max', fi_max + delta)
    _p(X, 'Fwd IAT Mean', np.where(paused, fm2, fi_mean)); _p(X, 'Fwd IAT Std', np.where(paused, fs2, fi_std))
    # 3. ralentissement : dilatation uniforme du temps
    D = 1.0 + th_d
    for c in TIME_FEATS:
        if c in FEAT_IDX: X[:, FEAT_IDX[c]] *= D
    # 4. débits recalculés (rapport nouveau / ancien : identité exacte si theta = 0)
    f_t = _div(dur0, _g(X, 'Flow Duration'), 1.0)
    f_b = _div(tf + add + tb, tf + tb, 1.0)
    _p(X, 'Flow Bytes/s', _g(X0, 'Flow Bytes/s') * f_b * f_t)
    for c in ['Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s']:
        _p(X, c, _g(X0, c) * f_t)
    X[:, T1_IDX] = np.maximum(X[:, T1_IDX], 0.0)
    return X.astype(np.float32)

WIN_MIN_THETA = 0.05
def perturb_t2(X0, theta):
    """T2 : T1 + theta[:, 3] ∈ [0, 1] -> fenêtre TCP initiale (échelle log de 1 à 65 535) si theta ≥ 0,05 et si un SYN a été vu."""
    X = perturb(X0, theta[:, :3])
    if WIN_FEAT in FEAT_IDX:
        j = FEAT_IDX[WIN_FEAT]; orig = np.asarray(X0)[:, j]
        new = np.round(np.exp(theta[:, 3] * np.log(65535.0)))
        X[:, j] = np.where((theta[:, 3] >= WIN_MIN_THETA) & (orig >= 0), new, orig)
    return X

_s = X_val[y_val == 1][:500]
print("perturb(θ = 0) == identité :", np.allclose(perturb(_s, np.zeros((len(_s), 3))), _s, rtol=1e-5, atol=1e-3))
print("perturb_t2(θ = 0) == identité :", np.allclose(perturb_t2(_s, np.zeros((len(_s), 4))), _s, rtol=1e-5, atol=1e-3))

# %% [markdown]
# ### 6.2 Invariants physiques
# Un flux modifié est jugé réaliste s'il **n'augmente pas** le taux de violation d'invariants que respecte tout flux réel (les flux d'origine en violent déjà quelques-uns : artefacts de CICFlowMeter), et s'il ne touche **aucune** variable hors du modèle de menace.

# %%
def violations(X, X0=None, allowed_nonmod=NONMOD_T1):
    X = np.asarray(X, dtype=np.float64); out = {}
    tol = lambda ref: 1e-3 * np.abs(ref) + 1e-3
    nf = _g(X, 'Total Fwd Packets')
    fmin, fmean, fmax = _g(X, 'Fwd Packet Length Min'), _g(X, 'Fwd Packet Length Mean'), _g(X, 'Fwd Packet Length Max')
    dur, imax, imean, imin = _g(X, 'Flow Duration'), _g(X, 'Flow IAT Max'), _g(X, 'Flow IAT Mean'), _g(X, 'Flow IAT Min')
    tf, tb = _g(X, 'Total Length of Fwd Packets'), _g(X, 'Total Length of Bwd Packets')
    out["valeur négative (variables T1)"] = (X[:, T1_IDX] < 0).any(axis=1)
    out["taille aller : min ≤ moy ≤ max"] = (nf > 0) & ((fmin > fmean + tol(fmean)) | (fmean > fmax + tol(fmax)))
    out["IAT : min ≤ moy ≤ max"] = (imin > imean + tol(imean)) | (imean > imax + tol(imax))
    out["durée ≥ plus grand IAT"] = dur < imax - tol(imax)
    out["durée ≥ somme des IAT aller"] = dur < _g(X, 'Fwd IAT Total') - tol(dur)
    out["Σ tailles aller = moy × nb paquets"] = np.abs(tf - fmean * nf) > 0.01 * tf + 1
    out["débit octets/s ≈ octets / durée"] = (dur > 0) & ((tf + tb) > 0) & (np.abs(_g(X, 'Flow Bytes/s') * dur / 1e6 - (tf + tb)) > 0.05 * (tf + tb) + 1)
    out["taille max globale ≥ taille max aller"] = _g(X, 'Max Packet Length') < fmax - tol(fmax)
    out["fenêtre TCP hors [-1, 65 535]"] = (_g(X, WIN_FEAT) < -1) | (_g(X, WIN_FEAT) > 65535)
    if X0 is not None:
        X0 = np.asarray(X0, dtype=np.float64)
        out["charge utile aller > max(MTU, valeur initiale)"] = fmax > np.maximum(_g(X0, 'Fwd Packet Length Max'), MTU_PAYLOAD) + 1e-6
        out["fenêtre TCP inventée sans SYN"] = (_g(X0, WIN_FEAT) < 0) & (_g(X, WIN_FEAT) != _g(X0, WIN_FEAT))
        out["variable hors modèle de menace changée"] = (X[:, allowed_nonmod] != X0[:, allowed_nonmod]).any(axis=1)
    return out

def realism_report(X0, X1, allowed_nonmod=NONMOD_T1):
    v0, v1 = violations(X0), violations(X1, X0, allowed_nonmod)
    added = np.column_stack([v1[k] & ~v0[k] for k in v0] + [v1[k] for k in v1 if k not in v0]).any(axis=1)
    rep = pd.DataFrame({"% violé (flux d'origine)": {k: 100 * v.mean() for k, v in v0.items()},
                        "% violé (flux modifiés)": {k: 100 * v.mean() for k, v in v1.items()}}).round(2)
    rep.loc["FLUX AVEC AU MOINS UNE VIOLATION AJOUTÉE PAR L'ATTAQUE"] = [np.nan, round(100 * added.mean(), 2)]
    return rep

# %% [markdown]
# ## 7. L'attaque d'évasion (boîte noire, budget de requêtes)
# Pour chaque flux d'attaque **initialement détecté** (score ≥ τ) :
# 1. requête n° 1 : score du flux d'origine ;
# 2. pendant les 30 % premières requêtes : **recherche aléatoire** de θ dans la boîte autorisée ;
# 3. ensuite : **escalade stochastique** (bruit gaussien autour du meilleur θ, conservé si le score baisse) ;
# 4. arrêt dès que score < τ (évasion) ou budget épuisé.
#
# En mode **étiquette seule** (section 9.2), la fonction de requête ne renvoie que 0/1 : l'escalade n'a plus de signal et l'attaque devient une recherche aléatoire pure.
#
# **Pièges évités.** L'évasion n'est mesurée que sur les flux initialement détectés ; le rappel après attaque compte **tous** les flux d'attaque échantillonnés (un flux déjà manqué reste manqué). Les flux attaqués sont plafonnés à `CAP_FAMILY` par famille : le rappel sous attaque est donc **équilibré par famille** ; sa valeur à ε = 0 sert de référence.

# %%
def evasion_attack(predict_fn, X0, eps, tau, *, perturb_fn=perturb, dim=3, free_dims=(), symmetric=False, hard_label=False,
                   budget=BUDGET, explore=0.3, sigma=0.25, mut_prob=1.0, seed=0):
    rng = np.random.default_rng(seed)
    X0 = np.asarray(X0, dtype=np.float32); n = len(X0)
    lo = np.full(dim, -min(eps, 1.0) if symmetric else 0.0); hi = np.full(dim, float(eps))
    for k in free_dims: lo[k], hi[k] = 0.0, 1.0                        # actions non bornées par ε (fenêtre TCP)
    query = (lambda X: (predict_fn(X) >= tau).astype(float)) if hard_label else predict_fn
    score0 = predict_fn(X0)
    best_s = (score0 >= tau).astype(float) if hard_label else score0.copy()
    best_th, q = np.zeros((n, dim)), np.ones(n, dtype=int)
    init_detected = score0 >= tau
    active = init_detected.copy() if (hi - lo).max() > 0 else np.zeros(n, dtype=bool)
    for t in range(1, budget):
        ii = np.flatnonzero(active)
        if len(ii) == 0: break
        if hard_label or t < explore * budget:
            cand = rng.uniform(lo, hi, (len(ii), dim))
        else:
            step = rng.normal(0, sigma * (hi - lo), (len(ii), dim))
            if mut_prob < 1: step *= rng.random((len(ii), dim)) < mut_prob
            cand = np.clip(best_th[ii] + step, lo, hi)
        s = query(perturb_fn(X0[ii], cand)); q[ii] += 1
        imp = s < best_s[ii]; jj = ii[imp]
        best_s[jj], best_th[jj] = s[imp], cand[imp]
        active[ii[s < tau]] = False
    final = predict_fn(perturb_fn(X0, best_th)) if (hi - lo).max() > 0 else score0
    return dict(theta=best_th, score=final, score0=score0, queries=q, init_detected=init_detected,
                success=init_detected & (final < tau), detected_after=final >= tau)

def sample_attack_flows(y, fam, cap, seed):
    rng = np.random.default_rng(seed); sel = []
    for f in np.unique(fam[y == 1]):
        ids = np.flatnonzero((y == 1) & (fam == f)); sel.append(rng.choice(ids, min(cap, len(ids)), replace=False))
    return np.concatenate(sel)

def proba_fn(model): return lambda X: model.predict_proba(X)[:, 1]

def wilson(k, n, z=1.96):
    if n == 0: return (np.nan, np.nan)
    p = k / n; d = 1 + z*z/n; c = (p + z*z/(2*n)) / d; h = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return c - h, c + h

def attack_cost(X0, theta):
    X1 = perturb(X0, theta[:, :3]).astype(np.float64); X0 = np.asarray(X0, dtype=np.float64)
    by0 = _g(X0, 'Total Length of Fwd Packets') + _g(X0, 'Total Length of Bwd Packets')
    by1 = _g(X1, 'Total Length of Fwd Packets') + _g(X1, 'Total Length of Bwd Packets')
    return 100 * (_div(by1, by0, 1.0) - 1), _div(_g(X1, 'Flow Duration'), _g(X0, 'Flow Duration'), 1.0)

# %% [markdown]
# ### 7.1 Développement de l'attaque sur la **validation** (le test reste intouché)

# %%
dev_idx = sample_attack_flows(y_val, fam_val, 40 if not QUICK else 15, SEED)
Xd, famd = X_val[dev_idx], fam_val[dev_idx]
t0 = time.time()
r_dev = evasion_attack(proba_fn(model_init), Xd, 1.0, TAU[DEF_NAME], seed=SEED)
print(f"{len(dev_idx)} flux | {r_dev['init_detected'].sum()} détectés au départ | évasions : {r_dev['success'].sum()} "
      f"({r_dev['success'][r_dev['init_detected']].mean():.1%} des détectés) | {time.time()-t0:.0f}s")
d = pd.DataFrame({"famille": famd, "detecte": r_dev["init_detected"], "evade": r_dev["success"], "requetes": r_dev["queries"]})
display(d[d.detecte].groupby("famille").agg(flux=("evade", "size"), taux_evasion=("evade", "mean"), requetes_medianes=("requetes", "median")).round(3))
print("Réalisme des flux modifiés (validation, ε = 1) :")
display(realism_report(Xd, perturb(Xd, r_dev["theta"])))
