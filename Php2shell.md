# TryHackMe — PHP2Shell

**Room :** `cvephp2shell` · **Difficulté :** exploitation mémoire / RCE
**CVE :** CVE-2026-109618 (fuite mémoire & contournement ASLR) + CVE-2026-109619 (exécution de code)

---

## Sommaire
- [Introduction](#introduction)
- [Contexte : où vit la faille ?](#contexte--où-vit-la-faille-)
- [CVE-2026-109618 — Fuite mémoire & contournement de l'ASLR](#cve-2026-109618--fuite-mémoire--contournement-de-laslr)
- [CVE-2026-109619 — Exécution de code](#cve-2026-109619--exécution-de-code)
- [Récupération du flag](#récupération-du-flag)
- [Remédiation & détection](#remédiation--détection)
- [Conclusion](#conclusion)

---

## Introduction

Cette room enchaîne **deux vulnérabilités de PHP** pour passer d'un simple crash
du moteur à une **exécution de commande à distance** (RCE) sur le serveur, le
tout sans aucune faille dans l'application web elle-même.

- **CVE-2026-109618** : transforme un pointeur périmé en **fuite de la mémoire**
  du worker PHP, ce qui permet de **contourner l'ASLR**.
- **CVE-2026-109619** : réutilise cette connaissance de la mémoire pour
  **détourner le mécanisme de nettoyage de PHP** et exécuter une commande
  arbitraire.

**Ce que cette room m'a appris :** la racine de l'attaque est un **use-after-free**.
En C, `free()` libère la mémoire mais ne remet pas le pointeur à `NULL` : celui-ci
continue de pointer vers une zone libérée (*dangling pointer*). Si cette zone est
réoccupée, le pointeur périmé décrit maintenant d'autres données — et c'est tout le
levier de l'exploit. J'ai aussi retenu côté défense que désactiver la fonctionnalité
déclencheuse (`session.upload_progress.enabled = 0`) suffit à couper la plupart des
variantes, en attendant le patch du runtime.

---

## Contexte : où vit la faille ?

Point clé de cette room : le bug **ne se trouve pas dans l'application**
(WordPress, Drupal, Laravel…) mais dans le **runtime PHP** lui-même, sous
toutes ces applications. Mettre à jour le CMS ne corrige donc rien — seul un
patch du moteur PHP règle le problème.

Quelques notions utiles :

- **ASLR** (*Address Space Layout Randomisation*) : défense qui charge le code
  et les données à des adresses **aléatoires** à chaque exécution, pour empêcher
  l'attaquant de savoir où se trouvent les choses en mémoire.
- **Heap** (le « tas ») : la zone mémoire où le programme range ses **données**
  pendant qu'il tourne.
- **Destructor** : fonction que PHP appelle automatiquement pour **libérer les
  ressources** d'une valeur qu'il détruit — normalement inoffensive.
- **Offset** : écart **fixe** entre deux positions en mémoire. L'ASLR déplace un
  bloc entier mais ne change pas l'organisation **à l'intérieur** : connaître une
  seule adresse réelle suffit donc à déduire toutes les autres par addition
  d'offsets.

---

## CVE-2026-109618 — Fuite mémoire & contournement de l'ASLR

PHP identifie les sessions avec un cookie `PHPSESSID` d'environ **32 caractères**.

Le mécanisme de la fuite :

1. Une condition de **manque de mémoire** est provoquée pendant la gestion d'un
   identifiant de session → cela laisse un **pointeur périmé** (*dangling
   pointer*) vers ce session id.
2. Une requête suivante **réoccupe l'espace libéré** : le pointeur périmé décrit
   maintenant une chaîne dont la **longueur a été gonflée** bien au-delà des
   vraies données (32 octets attendus → **~67 KB**).
3. Quand PHP renvoie le cookie dans l'en-tête `Set-Cookie: PHPSESSID`, il lit
   cette chaîne surdimensionnée et renvoie au client le **vrai id suivi de
   ~67 KB de mémoire du worker**.

Cette mémoire adjacente contient de **vraies adresses**. L'exploit lance la
fuite **deux fois** pour récupérer deux repères :

- **Stage 1 — heap leak** → `chunk base` : base du tas (les **données** de PHP).
- **Stage 2 — libphp leak** → `libphp base` : base de la bibliothèque PHP (le
  **code**), obtenue via un pointeur dont l'offset dans la lib est connu.

```
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x70d1a2c00000
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x70d1a4911000
```

Ces adresses changent à chaque run (c'est l'ASLR qui fait son travail), mais
l'attaquant les **lit** au lieu de les deviner : l'ASLR est **neutralisé**.

Une fois le `heap leak` et le `libphp leak` obtenus, on connaît les **bases
réelles** du tas et de la bibliothèque PHP. Les offsets internes étant fixes,
on en **déduit par calcul** (base + offset) n'importe quelle autre adresse de
ces zones — notamment celle de `system()` utilisée par la CVE suivante. On ne
*devine* donc jamais une adresse : on la *calcule*, ce qui rend l'ASLR inutile.

---

## CVE-2026-109619 — Exécution de code

La fuite a révélé **où** se trouve tout en mémoire. Cette seconde CVE transforme
cette connaissance en **commande exécutée sur le serveur**.

Le principe :

1. L'exploit **réoccupe la référence périmée** avec un **faux objet interne**
   (une `HashTable` forgée).
2. Le pointeur de destructor de ce faux objet, `pDestructor`, est remplacé par
   l'**adresse de `system()`** à l'intérieur de libphp — adresse connue grâce à
   la fuite précédente.
3. Quand le moteur fait son **ménage de fin de requête**, il croit appeler un
   destructor inoffensif… et appelle en réalité **`system()`**, avec des octets
   contrôlés par l'attaquant comme argument.

La commande s'exécute sous l'identité de l'utilisateur du serveur web :
**`www-data`**.

Toute la chaîne tient en **quatre requêtes** (de simples POST multipart) :

| Étape        | Action                                               |
|--------------|------------------------------------------------------|
| 1 Rotate     | crasher un worker, en relancer un neuf               |
| 2 Leak heap  | fuite n°1 → `chunk base`                              |
| 3 Leak libphp| fuite n°2 → `libphp base` → **ASLR neutralisé**      |
| 4 Forge      | faux `HashTable`, `pDestructor = system()` → **RCE** |

Lancer l'exploit sans argument de commande exécute toute la chaîne et prouve
l'exécution avec `id` :

```bash
python3 exploit.py -u http://127.0.0.1:8088/index.php
```

```
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Récupération du flag

Le tuyau de l'exploit est minuscule (~14 octets pour la commande), donc le flag
est déposé dans un fichier d'un dossier **partagé** (`out`) que l'outil relit
ensuite.

```bash
python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'cat /f>/out/p1' --proof-file out/p1
```

Décomposition de la commande :

| Partie                        | Rôle                                               |
|-------------------------------|----------------------------------------------------|
| `-u http://.../index.php`     | la cible à attaquer                                |
| `-c 'cat /f>/out/p1'`         | commande exécutée sur la victime (`system()`)      |
| `cat /f`                      | lit le flag sur la cible                           |
| `>/out/p1`                    | écrit le résultat dans le dossier partagé `out`    |
| `--proof-file out/p1`         | relit ce fichier et affiche son contenu            |

```
PROOF: THM{b4ilout_l3aves_th3_h3ap_dang1ing}
```

**Astuce :** la corruption mémoire est probabiliste. Si un run s'arrête à l'étape
de fuite, il suffit de le relancer — l'exploit réessaie les étapes fragiles.

---

## Remédiation & détection

### Le vrai correctif
Patcher **PHP lui-même** vers une version corrigée (**8.5.12, 8.4.27, 8.3.36 ou
8.2.35**), puis **redémarrer tous les workers**. Mettre à jour le CMS ne corrige
rien, car la faille est dans le runtime.

### Mesures temporaires (aucune ne remplace le patch)
- `session.upload_progress.enabled = 0` → supprime le déclencheur
- `opcache.enable = 0` → gêne l'exécution de code
- `fatal_error_backtraces = 0` (PHP 8.5) → vise spécifiquement CVE-2026-109619
- rejeter les requêtes `multipart/form-data` → bloque la livraison (casse les
  uploads légitimes)
- exécuter PHP en **moindre privilège** → limite les dégâts

### Ce qui ne marche PAS
Un **WAF applicatif** tournant comme module PHP est inutile : il n'inspecte le
trafic qu'après que PHP a passé la main à l'application, alors que l'attaque fait
ses dégâts **pendant l'analyse de la requête**. La protection doit être dans le
runtime patché ou à une couche **devant** PHP.

### Détection
- valeurs `PHPSESSID` **anormalement grandes** dans les en-têtes `Set-Cookie`
- gros **POST multipart** avec énormément de champs, portant
  `PHP_SESSION_UPLOAD_PROGRESS`
- **crashs de workers** PHP et erreurs **out-of-memory** dans les logs

La combinaison de ces signaux est un indicateur fort de l'attaque.

---

## Conclusion

**Bilan :** cette room montre qu'une faille dans le **runtime** (et non dans
l'application) peut mener à une RCE complète, invisible pour les défenses
classiques comme un WAF applicatif. Le RCE obtenu s'exécute sous `www-data`, un
utilisateur à **privilèges limités** : ce n'est qu'un premier accès. Dans une
attaque réelle, l'étape suivante serait l'**escalade de privilèges** pour viser
`root` et prendre le contrôle total de la machine.
