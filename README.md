# AF-GCN-GAT_wGS

Ce dépôt contient le code utilisé pour notre article accepté à **COMMA24**, disponible sur [arxiv](https://arxiv.org/pdf/2404.18672). Ce projet met en œuvre des réseaux de neurones graphiques (**GCN** et **GAT**) avec des sémantiques graduées pour l'argumentation abstraire.

## Installation

### 1. Prérequis

Avant d'utiliser ce projet, assurez-vous d'installer les dépendances suivantes :

- **PyTorch** : [https://pytorch.org/get-started/locally/](https://pytorch.org/get-started/locally/)
- **DGL** : [https://www.dgl.ai/pages/start.html](https://www.dgl.ai/pages/start.html)

Installez-les avec pip :

```bash
pip install torch dgl
```

- **Rust** : Requis pour compiler la bibliothèque `af_reader_py`. Installez-le en suivant les instructions officielles :  
  [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

- **Maturin** : Utilisé pour construire `af_reader_py`. Installez-le avec :

```bash
pip install maturin
```

### 2. Installer `af_reader_py`

Le module **`af_reader_py`**, développé pour ce projet, permet d'intégrer les sémantiques graduées comme **hcat** et le calcul de la grounded pour l'argumentation abstraire ainsi que pour lire le fichier. Vous pouvez l'installer de deux manières :

#### Via `pip`
```bash
pip install af_reader_py
```

#### Manuellement avec `maturin`
Si vous souhaitez compiler et installer la bibliothèque localement :

```bash
cd af_reader_py
maturin build -r
pip install the_path_of_the_wheel
```
## Disposition

Les fichiers pour l'entrainement du model commence par un training_
Les fichiers commencant par afvgcn* sont les scripts qui embarque le model correspondant et l'utilise comme solver.

## Utilisation
For the training part
```bash
    python3 training_....py 
```
For the solver part
```bash
    python3 solver_name.py FILE_PATH TASK ARG_ID
```

## Références

Si vous utilisez ce projet, veuillez citer notre article :

```
@article{votre_reference,
  title={Titre de l'article},
  author={Votre nom et co-auteurs},
  journal={COMMA24},
  year={2024},
  archivePrefix={arXiv},
  eprint={2404.18672}
}
```