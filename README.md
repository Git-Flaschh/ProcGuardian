
# ProcGuardian - Surveillance de processus

![ProcGuardian Logo](logo.jpg "ProcGuardian - Surveillance de processus")

Ce dépôt contient un démon de surveillance des processus pour les systèmes Linux. Il est conçu pour détecter des patterns potentiellement malveillants ou indicateurs de compromission dans les processus en cours d'exécution.

## Installation

1. Téléchargez le fichier .deb depuis ce dépôt.
2. Installez le paquet en utilisant la commande suivante :
```bash
sudo dpkg -i ProcGuardian.deb
```

3. Installez Python si ce n'est pas déjà fait :
```bash
sudo apt-get update
sudo apt-get install python3
```

4. Installez les dépendances requises manuellement :
```bash
sudo apt install python3-pip #non nécessaire avec Python >= 3.4
pip3 install psutil
```


## Utilisation

Le démon peut être contrôlé à l'aide des commandes suivantes :

- Pour démarrer le démon :

```bash
sudo procguardian start
```

- Pour arrêter le démon :

```bash
sudo procguardian stop
```

- Pour vérifier le statut du démon :

```bash
sudo procguardian status
```
- Pour afficher les alertes sur les processus potentiellement suspects:
```bash
sudo procguardian logs suspect
```
```bash
cat /var/log/procguard/alerts.log
```
- Pour afficher l'aide et les instructions d'utilisation :

```bash
procguardian --help
```


## Fonctionnalités

Le démon de surveillance des processus offre les fonctionnalités suivantes :

1. **Détection continue** : Surveille en permanence la liste des processus en cours d'exécution.
2. **Patterns suspects** : Identifie des configurations potentiellement dangereuses, telles que :
    - Tomcat exécuté en tant que root
    - Processus inconnus avec des privilèges root
    - Processus exécutés depuis des répertoires suspects (ex : /tmp/)
3. **Alertes et journalisation** : Génère des alertes et des logs pour les activités suspectes détectées.

## Prérequis

- Système d'exploitation Linux
- Python 3.6 ou supérieur
- pip si version de Python < 3.4
- Bibliothèques Python :
    - psutil (installée manuellement avec pip3)
    - time (incluse dans la bibliothèque standard Python)


## Dépannage

Si vous rencontrez des problèmes, veuillez consulter les logs du système :

```bash
sudo procguardian logs
```
```bash
sudo journalctl -u procguardian
```


## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou à soumettre une pull request.

