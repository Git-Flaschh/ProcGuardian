#!/usr/bin/env python3
import psutil
import time

def is_sudo(proc):
    """
    Détecte tout processus 'sudo'
    """
    try:
        if proc.name().lower() == "sudo":
            return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def is_tomcat_as_root(proc):
    """
    Détecte un Tomcat (java/catalina) lancé en root
    """
    try:
        name = proc.name().lower()
        username = proc.username()
        if ("java" in name or "catalina" in name) and username == "root":
            return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

#def is_bash_child_of_nginx(proc):
#    """
#   Détecte un bash dont le parent est nginx
#    """
#    try:
#        name = proc.name().lower()
#        if name == "bash":
#            parent = proc.parent()
#            if parent and parent.name().lower() == "nginx":
#                return True
#        return False
#    except (psutil.NoSuchProcess, psutil.AccessDenied):
#        return False

def main_loop(interval=5):
    """
    Boucle principale.
    - interval : intervalle (en secondes) entre chaque scan.
    """
    while True:
        # Parcourt tous les processus avec les infos pid, name, username
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                p_name = proc.name().lower()
                p_user = proc.username()

                # -- DEBUT BLOC DE DEBUG --
                # Affiche le PID, le nom, l'utilisateur pour TOUT processus
                print(f"DEBUG: PID={proc.pid}, NAME={p_name}, USER={p_user}")
                # -- FIN BLOC DE DEBUG --

                # Vérifie si on détecte un "Tomcat (java) en root"
                if is_tomcat_as_root(proc):
                    print(f"[ALERTE] Tomcat (java) lancé en root ! PID={proc.pid}")

                # Vérifie si on détecte un "bash enfant de nginx"
#                if is_bash_child_of_nginx(proc):
#                    print(f"[ALERTE] bash enfant de nginx détecté ! PID={proc.pid}")

                # Vérifie si on détecte un processus 'sudo'
                if is_sudo(proc):
                    print(f"[ALERTE] Un processus 'sudo' détecté ! PID={proc.pid}")

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                # En cas de process disparu ou accès refusé
                print(f"DEBUG ERROR pour PID={proc.pid}: {e}")

        # Pause avant le prochain scan
        time.sleep(interval)

if __name__ == "__main__":
    # Lance la boucle principale
    main_loop(interval=10)  # Scan toutes les 10 secondes
