import subprocess
import time
import sys

PYTHON = sys.executable

def launch_process(command_list, name):
    """Launches a background process and forces output to be read immediately."""
    print(f"\n[SYSTEM] Launching {name}...")
    cmd = [PYTHON, "-u"] + command_list
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0)

def search_logs(process, search_string, timeout=5):
    """Scans the output of a background process for a specific string."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        line = process.stdout.readline()
        if line:
            print(f"  -> {line.strip()}")
            if search_string in line:
                return True
    return False

def run_demonstration():
    print("==================================================")
    print("  STARTING UNIQUE SECURE MESSAGING DEMONSTRATION  ")
    print("==================================================")

    # --- PHASE 1: THE BASELINE (Unprotected, No Attacker) ---
    print("\n\n>>> PHASE 1: Baseline Communication (No Attacker) <<<")
    
    server1 = launch_process(["secure_server.py", "--port", "8000"], "Unprotected Server")
    time.sleep(1)
    
    bob1 = launch_process(["secure_client.py", "Bob", "--port", "8000"], "Bob")
    time.sleep(1)
    
    alice1 = launch_process(["secure_client.py", "Alice", "--port", "8000"], "Alice")
    time.sleep(1)

    print("\n[ACTION] Alice is sending a message directly to Bob...")
    alice1.stdin.write("msg Bob HelloBaseline\n")
    alice1.stdin.flush()

    if search_logs(bob1, "HelloBaseline", timeout=10):
        print("\n[RESULT] BASELINE SUCCESS: Basic end-to-end encryption works.")
    else:
        print("\n[RESULT] FAILED: Bob didn't get the message.")

    server1.terminate(); bob1.terminate(); alice1.terminate()
    time.sleep(2)


    # --- PHASE 2: THE VULNERABILITY (Unprotected, MITM Active) ---
    print("\n\n>>> PHASE 2: MITM Attack on Unprotected Network <<<")
    
    server2 = launch_process(["secure_server.py", "--port", "8000"], "Unprotected Server")
    time.sleep(1)
    
    eve2 = launch_process(["attacker_eve.py", "--listen", "9000", "--target", "8000"], "Eve Proxy")
    time.sleep(1)
    
    bob2 = launch_process(["secure_client.py", "Bob", "--port", "8000"], "Bob (Safe Route)")
    time.sleep(1)
    
    alice2 = launch_process(["secure_client.py", "Alice", "--port", "9000"], "Alice (Trapped Route)")
    time.sleep(1)

    print("\n[ACTION] Alice is sending a secret to Bob...")
    alice2.stdin.write("msg Bob TheSecretPassword\n")
    alice2.stdin.flush()

    if search_logs(eve2, "SECRET INTERCEPTED", timeout=10):
        print("\n[RESULT] VULNERABILITY CONFIRMED: Eve successfully intercepted the message!")
    else:
        print("\n[RESULT] FAILED: Eve missed the message.")

    server2.terminate(); eve2.terminate(); bob2.terminate(); alice2.terminate()
    time.sleep(2)


    # --- PHASE 3: THE SOLUTION (Secure Mode, MITM Active) ---
    print("\n\n>>> PHASE 3: MITM Attack on Secure CA Network <<<")
    
    server3 = launch_process(["secure_server.py", "--port", "8000", "--secure"], "Secure CA Server")
    time.sleep(1)
    
    eve3 = launch_process(["attacker_eve.py", "--listen", "9000", "--target", "8000"], "Eve Proxy")
    time.sleep(1)
    
    bob3 = launch_process(["secure_client.py", "Bob", "--port", "9000", "--secure"], "Bob (Secure)")
    time.sleep(1)
    
    alice3 = launch_process(["secure_client.py", "Alice", "--port", "9000", "--secure"], "Alice (Secure)")
    time.sleep(1)

    print("\n[ACTION] Alice is sending a secret to Bob...")
    alice3.stdin.write("msg Bob ThisWillFail\n")
    alice3.stdin.flush()

    if search_logs(alice3, "MITM DETECTED", timeout=10):
        print("\n[RESULT] SECURITY SUCCESS: Alice verified the CA signature and blocked Eve!")
    else:
        print("\n[RESULT] FAILED: Alice did not detect Eve.")

    server3.terminate(); eve3.terminate(); bob3.terminate(); alice3.terminate()

    print("\n==================================================")
    print("               DEMONSTRATION COMPLETE               ")
    print("==================================================")

if __name__ == "__main__":
    try:
        run_demonstration()
    except KeyboardInterrupt:
        print("\nDemo aborted.")