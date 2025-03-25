#!/usr/bin/env python3
import psutil
import time
import os
import argparse
from datetime import datetime

# === CONFIGURATION DU CHEMIN DE LOG ===
LOG_FILE = None
QUIET_MODE = False
DEBUG_ONLY = False
EXCLUDED_USERS = []
ALERTED_PIDS = set()  # Ensemble pour mémoriser les PIDs déjà alertés

def init_logging(logfile_path):
    global LOG_FILE
    LOG_FILE = logfile_path
    log_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            print(f"Erreur : impossible de créer {log_dir}. Lancez le script en sudo.")
            exit(1)

def write_alert_log(message):
    now = datetime.now().strftime("%H:%M:%S %d:%m:%Y")
    formatted_message = f"{now} [ALERT] : {message}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(formatted_message)
    except PermissionError:
        if not QUIET_MODE:
            print(f"Erreur : impossible d'écrire dans {LOG_FILE}. Lancez le script avec sudo.")
        exit(1)

def is_sudo(proc):
    try:
        if proc.name().lower() == "sudo":
            cmdline = proc.cmdline()  # Recupere la commande complete lancee par sudo
            command = " ".join(cmdline[1:])  # Exclut 'sudo' de la commande
            return True, command
        return False, ""
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False, ""

def is_tomcat_as_root(proc):
    try:
        name = proc.name().lower()
        username = proc.username()
        return ("java" in name or "catalina" in name) and username == "root"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

# def is_bash_parent_nginx(proc):
#     try:
#         parent = proc.parent()
#         if parent and parent.name().lower() == "nginx":
#             return True
#         return False
#     except (psutil.NoSuchProcess, psutil.AccessDenied):
#         return False

def is_python_as_root(proc):
    try:
        name = proc.name().lower()
        username = proc.username()
        return "python" in name and username == "root"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def is_process_using_suspect_files(proc, suspect_paths=["/tmp", "/var/tmp"]):
    try:
        open_files = proc.open_files()
        for file in open_files:
            if any(file.path.startswith(path) for path in suspect_paths):
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def is_process_with_suspect_args(proc, suspect_args=["wget", "curl", "nc", "ss"]):
    try:
        cmdline = proc.cmdline()
        for arg in cmdline:
            if any(suspect in arg for suspect in suspect_args):
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def process_alert(proc, alert_type, additional_info=""):
    """Vérifie si une alerte pour ce PID a déjà  été déclenché."""
    global ALERTED_PIDS

    # Si le PID a déjà  été alerté récemment, on ne répète pas l'alerte
    if proc.pid in ALERTED_PIDS:
        return False
    
    ALERTED_PIDS.add(proc.pid)  # Ajouter le PID Ã  l'ensemble des alertes
    alert_msg = f"{alert_type} : PID={proc.pid}, NAME={proc.name()}, USER={proc.username()}, {additional_info}"
    
    if not QUIET_MODE:
        print(f"[SUSPECT] {alert_msg}")
    write_alert_log(alert_msg)
    return True

def main_loop(interval):
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                p_name = proc.name().lower()
                p_user = proc.username()

                if p_user in EXCLUDED_USERS:
                    continue

                if not QUIET_MODE and not DEBUG_ONLY:
                    print(f"DEBUG: PID={proc.pid}, NAME={p_name}, USER={p_user}")

                if is_tomcat_as_root(proc):
                    process_alert(proc, "Tomcat (java) lancÃ© en root")

                # Vérification des processus 'sudo' et affiche la commande lancée
                is_sudo_process, sudo_command = is_sudo(proc)
                if is_sudo_process:
                    process_alert(proc, "Processus 'sudo' détecté", f"Commande lancée : {sudo_command}")

                # if is_bash_parent_nginx(proc):
                #     process_alert(proc, "Bash lancÃ© depuis le parent Nginx")

                if is_python_as_root(proc):
                    process_alert(proc, "Processus Python lancé en root détecté")
                
                if is_process_using_suspect_files(proc):
                    process_alert(proc, "Processus lancé depuis un fichier suspect")

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                if not QUIET_MODE:
                    print(f"DEBUG ERROR pour PID={proc.pid}: {e}")

        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Surveillance des processus sensibles sur le système.")
    parser.add_argument("-i", "--interval", type=int, default=10, help="Intervalle entre chaque scan (en secondes).")
    parser.add_argument("-q", "--quiet", action="store_true", help="Mode silencieux (exécution sans affichage console).")
    parser.add_argument("-d", "--debug", action="store_true", help="Affiche uniquement les alertes (pas les DEBUG).")
    parser.add_argument("-l", "--logfile", default="/var/log/procguard/alerts.log", help="Chemin du fichier log.")
    parser.add_argument("--exclude-user", type=str, help="Exclure des utilisateurs (séparé par des virgules).")

    args = parser.parse_args()

    QUIET_MODE = args.quiet
    DEBUG_ONLY = args.debug
    EXCLUDED_USERS = [u.strip() for u in args.exclude_user.split(",")] if args.exclude_user else []

    init_logging(args.logfile)

    try:
        main_loop(interval=args.interval)
    except KeyboardInterrupt:
        if not QUIET_MODE:
            print("\nArrêt du script demandé par l'utilisateur (CTRL+C).")
        exit(0)
