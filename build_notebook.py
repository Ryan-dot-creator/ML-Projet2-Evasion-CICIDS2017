"""Assemble le notebook à partir des sources par rôle (src/*.py, format jupytext « percent »).

    python build_notebook.py                 # écrit Projet2_Evasion_CICIDS2017.ipynb (sans sorties)
    python build_notebook.py --execute       # puis l'exécute de haut en bas (≈ 25 min sur 2 cœurs, QUICK = False)
    python build_notebook.py --keep-outputs  # réassemble en conservant les sorties déjà calculées ; refusé si une
                                             # cellule de code a changé (utile après une retouche du texte seulement)

Chaque fichier de src/ appartient à un rôle (préfixe : commun, defenseur, attaquant) ; l'ordre des préfixes
numériques donne l'ordre du notebook.
"""
import glob, os, subprocess, sys
import jupytext, nbformat

OUT = "Projet2_Evasion_CICIDS2017.ipynb"
source = "".join(open(f, encoding="utf-8").read().rstrip("\n") + "\n\n" for f in sorted(glob.glob("src/[0-9]*.py")))
nb = jupytext.reads(source, fmt="py:percent")
nb.metadata = {"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"},
               "language_info": {"name": "python"}}
_, nb = nbformat.validator.normalize(nb)
nb = nbformat.from_dict(nb)

if "--keep-outputs" in sys.argv:
    assert os.path.exists(OUT), f"{OUT} introuvable : rien à conserver"
    old = [c for c in nbformat.read(OUT, as_version=4).cells if c.cell_type == "code"]
    new = [c for c in nb.cells if c.cell_type == "code"]
    changed = [i for i, (a, b) in enumerate(zip(new, old)) if a.source.strip() != b.source.strip()]
    if len(old) != len(new) or changed:
        sys.exit(f"Le code a changé (cellules de code n° {changed or 'ajout/suppression'}) : relancer avec --execute.")
    for a, b in zip(new, old):
        a.outputs, a.execution_count = b.outputs, b.execution_count

nbformat.validate(nb)
nbformat.write(nb, OUT)
print(f"{OUT} : {len(nb.cells)} cellules")
if "--execute" in sys.argv:
    subprocess.run(["jupyter", "nbconvert", "--to", "notebook", "--execute", "--inplace",
                    "--ExecutePreprocessor.timeout=-1", OUT], check=True)
