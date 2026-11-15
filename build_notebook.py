"""Assemble le notebook à partir des sources par rôle (src/*.py, format jupytext « percent »).

    python build_notebook.py            # écrit Projet2_Evasion_CICIDS2017.ipynb (sans sorties)
    python build_notebook.py --execute  # puis l'exécute de haut en bas (≈ 35 min sur 2 cœurs, QUICK = False)

Chaque fichier de src/ appartient à un rôle (préfixe : commun, defenseur, attaquant) ; l'ordre alphabétique
des préfixes numériques donne l'ordre du notebook.
"""
import glob, subprocess, sys
import jupytext, nbformat

OUT = "Projet2_Evasion_CICIDS2017.ipynb"
source = "".join(open(f, encoding="utf-8").read().rstrip("\n") + "\n\n" for f in sorted(glob.glob("src/[0-9]*.py")))
nb = jupytext.reads(source, fmt="py:percent")
nb.metadata = {"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"},
               "language_info": {"name": "python"}}
_, nb = nbformat.validator.normalize(nb)
nb = nbformat.from_dict(nb)
nbformat.validate(nb)
nbformat.write(nb, OUT)
print(f"{OUT} : {len(nb.cells)} cellules")
if "--execute" in sys.argv:
    subprocess.run(["jupyter", "nbconvert", "--to", "notebook", "--execute", "--inplace",
                    "--ExecutePreprocessor.timeout=-1", OUT], check=True)
