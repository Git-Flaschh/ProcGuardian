#!/usr/bin/env python3
import psutil       # Bibliothèque permettant d'interagir avec les processus système
import time         # Pour les temporisations (sleep)
import os           # Pour la gestion des chemins de fichiers/répertoires
import argparse     # Pour la gestion des arguments en ligne de commande
from datetime import datetime  # Pour gérer les dates et heures (timestamp des logs)

# === CONFIGURATION DU CHEMIN DE LOG ET AUTRES PARAMÈTRES GLOBAUX ===
LOG_FILE = None      # Contiendra le chemin complet du fichier de log (ex. /var/log/procguard/alerts.log)
QUIET_MODE = False   # Si True, le script s'exécute en "mode silencieux" : aucune sortie console n'est affichée
DEBUG_ONLY = False   # Si True, seuls les messages d'alerte seront affichés, pas les informations de débogage
EXCLUDED_USERS = []  # Liste d’utilisateurs à ignorer (aucune alerte ne sera déclenchée pour ces utilisateurs)
ALERTED_PIDS = set() # Ensemble des PIDs déjà signalés, pour éviter de déclencher plusieurs fois la même alerte

def init_logging(logfile_path):
    """
    Initialise le fichier de log et crée le répertoire s'il n'existe pas.
    
    :param logfile_path: Chemin complet du fichier de log (ex. /var/log/procguard/alerts.log).
    """
    global LOG_FILE
    LOG_FILE = logfile_path
    log_dir = os.path.dirname(LOG_FILE)
    
    # Création du répertoire parent si nécessaire
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            print(f"Erreur : impossible de créer {log_dir}. Lancez le script en sudo.")
            exit(1)

def write_alert_log(message):
    """
    Écrit un message d'alerte dans le fichier de log,
    en le préfixant par la date et l'heure de l'événement.
    
    :param message: Message à enregistrer dans le log.
    """
    now = datetime.now().strftime("%H:%M:%S %d:%m:%Y")  # Format HH:MM:SS DD:MM:YYYY
    formatted_message = f"{now} [ALERT] : {message}\n"
    
    # Écriture dans le fichier de log
    try:
        with open(LOG_FILE, "a") as f:
            f.write(formatted_message)
    except PermissionError:
        if not QUIET_MODE:
            print(f"Erreur : impossible d'écrire dans {LOG_FILE}. Lancez le script avec sudo.")
        exit(1)

def is_sudo(proc):
    """
    Détecte si un processus est un 'sudo' et récupère la commande exécutée.
    
    :param proc: Objet psutil.Process
    :return: (bool, str) -> (True/False, commande exécutée ou chaîne vide)
    """
    try:
        if proc.name().lower() == "sudo":
            # La cmdline contient la liste des arguments de la commande lancée avec sudo
            cmdline = proc.cmdline()
            # On exclut la première partie "sudo" pour ne récupérer que la commande qui suit
            command = " ".join(cmdline[1:])
            return True, command
        return False, ""
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        # Si le process a disparu ou qu'on n'a pas accès à ses infos
        return False, ""

def is_tomcat_as_root(proc):
    """
    Détecte si un processus Tomcat (Java) tourne en tant que root.
    Vérifie le nom du processus (java / catalina) et son utilisateur.
    
    :param proc: Objet psutil.Process
    :return: bool
    """
    try:
        name = proc.name().lower()
        username = proc.username()
        # "java" ou "catalina" dans le nom, ET utilisateur root
        return ("java" in name or "catalina" in name) and username == "root"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

# def is_bash_parent_nginx(proc):
#     """
#     Exemple commenté : Détecte si 'bash' est un sous-processus direct de 'nginx'
#     (utile pour détecter un shell intéractif lancé depuis un serveur web).
#     """
#     try:
#         parent = proc.parent()
#         if parent and parent.name().lower() == "nginx":
#             return True
#         return False
#     except (psutil.NoSuchProcess, psutil.AccessDenied):
#         return False

def is_python_as_root(proc):
    """
    Détecte si un processus Python tourne en tant que root.
    
    :param proc: Objet psutil.Process
    :return: bool
    """
    try:
        name = proc.name().lower()
        username = proc.username()
        # "python" dans le nom, ET utilisateur root
        return "python" in name and username == "root"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def is_process_using_suspect_files(proc, suspect_paths=["/tmp", "/var/tmp"]):
    """
    Vérifie si un processus utilise des fichiers suspects dans des répertoires sensibles
    comme /tmp ou /var/tmp (souvent utilisés pour des scripts malveillants).
    
    :param proc: Objet psutil.Process
    :param suspect_paths: Liste des chemins suspects à vérifier
    :return: bool
    """
    try:
        open_files = proc.open_files()  # Récupère la liste des fichiers ouverts par le processus
        for file in open_files:
            # Vérifie si le chemin de fichier commence par /tmp ou /var/tmp
            if any(file.path.startswith(path) for path in suspect_paths):
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def is_process_with_suspect_args(proc, suspect_args=["wget", "curl", "nc", "ss"]):
    """
    Vérifie si un processus contient des arguments suspects (ex : wget, curl, nc, ss).
    
    :param proc: Objet psutil.Process
    :param suspect_args: Liste des arguments/applications à surveiller
    :return: bool
    """
    try:
        cmdline = proc.cmdline()  # Liste des arguments de la ligne de commande
        for arg in cmdline:
            # On regarde si un des mots-clés (ex. wget) apparaît dans l'argument
            if any(suspect in arg for suspect in suspect_args):
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def process_alert(proc, alert_type, additional_info=""):
    """
    Gère la création d'une alerte pour un process donné,
    en évitant de dupliquer l'alerte si le même PID est déjà signalé.
    
    :param proc: Objet psutil.Process
    :param alert_type: Type d'alerte, ex : "Processus Python lancé en root détecté"
    :param additional_info: Information complémentaire (ex. commande lancée)
    :return: bool (True si une alerte a été déclenchée, False sinon)
    """
    global ALERTED_PIDS

    # Vérifie si on a déjà alerté pour ce PID
    if proc.pid in ALERTED_PIDS:
        return False
    
    # On mémorise ce PID pour éviter de répéter l'alerte
    ALERTED_PIDS.add(proc.pid)

    # Message d'alerte détaillé
    alert_msg = f"{alert_type} : PID={proc.pid}, NAME={proc.name()}, USER={proc.username()}, {additional_info}"
    
    # Affiche l'alerte dans la console, sauf si QUIET_MODE est activé
    if not QUIET_MODE:
        print(f"[SUSPECT] {alert_msg}")
    
    # Écrit l'alerte dans le fichier de log
    write_alert_log(alert_msg)
    return True

def main_loop(interval):
    """
    Boucle principale qui surveille les processus à intervalles réguliers.
    Contrôle tout d'abord les processus via psutil.process_iter(),
    puis applique les différentes fonctions de détection.
    
    :param interval: Intervalle (en secondes) entre chaque itération de scan.
    """
    while True:
        # Parcourt tous les processus en récupérant pid, name, username
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                p_name = proc.name().lower()
                p_user = proc.username()

                # Ignore les utilisateurs exclus, si fournis
                if p_user in EXCLUDED_USERS:
                    continue

                # Affiche un message DEBUG si on n'est pas en QUIET_MODE et qu'on n'est pas en DEBUG_ONLY
                if not QUIET_MODE and not DEBUG_ONLY:
                    print(f"DEBUG: PID={proc.pid}, NAME={p_name}, USER={p_user}")

                # 1) Détecte un Tomcat/Java lancé en root
                if is_tomcat_as_root(proc):
                    process_alert(proc, "Tomcat (java) lancé en root")

                # 2) Détecte un processus 'sudo' et récupère la commande
                is_sudo_process, sudo_command = is_sudo(proc)
                if is_sudo_process:
                    process_alert(proc, "Processus 'sudo' détecté", f"Commande lancée : {sudo_command}")

                # 3) Détecte un processus Python lancé en root
                if is_python_as_root(proc):
                    process_alert(proc, "Processus Python lancé en root détecté")
                
                # 4) Détecte un process qui utilise des fichiers dans /tmp ou /var/tmp
                if is_process_using_suspect_files(proc):
                    process_alert(proc, "Processus lancé depuis un fichier suspect")

                # 5) [optionnel/possible] Détecte un process avec arguments suspects (wget, curl, etc.)
                # if is_process_with_suspect_args(proc):
                #     process_alert(proc, "Processus utilisant des arguments suspects")

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                # En cas d'exception, on affiche un message d'erreur (si QUIET_MODE est faux)
                if not QUIET_MODE:
                    print(f"DEBUG ERROR pour PID={proc.pid}: {e}")

        # Attente avant le prochain scan
        time.sleep(interval)

if __name__ == "__main__":
    # On prépare le parseur d'arguments pour personnaliser l'exécution du script
    parser = argparse.ArgumentParser(description="Surveillance des processus sensibles sur le système.")
    parser.add_argument("-i", "--interval", type=int, default=10,
                        help="Intervalle entre chaque scan (en secondes).")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Mode silencieux (exécution sans affichage console).")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Affiche uniquement les alertes (pas les DEBUG).")
    parser.add_argument("-l", "--logfile", default="/var/log/procguard/alerts.log",
                        help="Chemin du fichier log.")
    parser.add_argument("--exclude-user", type=str,
                        help="Exclure des utilisateurs (séparé par des virgules).")

    # Récupération et parsing des arguments
    args = parser.parse_args()

    # Mise à jour des variables globales selon les arguments reçus
    QUIET_MODE = args.quiet
    DEBUG_ONLY = args.debug
    # Si l'option --exclude-user est fournie, on crée la liste des utilisateurs à exclure
    EXCLUDED_USERS = [u.strip() for u in args.exclude_user.split(",")] if args.exclude_user else []

    # Initialisation du logging
    init_logging(args.logfile)

    # Exécution de la boucle principale dans un bloc try/except,
    # pour gérer le CTRL+C (KeyboardInterrupt)
    try:
        main_loop(interval=args.interval)
    except KeyboardInterrupt:
        # Interception du CTRL+C pour un arrêt propre
        if not QUIET_MODE:
            print("\nArrêt du script demandé par l'utilisateur (CTRL+C).")
        exit(0)
