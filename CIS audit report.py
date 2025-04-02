import subprocess

def check_firewall_status():
    try:
        result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True)
        if "ON" in result.stdout:
            print("[PASS] Firewall is enabled.")
        else:
            print("[FAIL] Firewall is disabled.")
    except Exception as e:
        print(f"[ERROR] Unable to check firewall status: {e}")

def check_windows_updates():
    try:
        subprocess.run(["powershell", "Import-Module PSWindowsUpdate"], check=True)
        result = subprocess.run(["powershell", "Get-WindowsUpdate"], capture_output=True, text=True)
        if result.returncode == 0:
            if "No updates available" in result.stdout:
                print("[PASS] Windows is up to date.")
            else:
                print("[FAIL] Windows updates are available.")
        else:
            print("[ERROR] Unable to check Windows updates.")
    except Exception as e:
        print(f"[ERROR] Unable to check Windows updates: {e}")

def check_password_policy():
    try:
        result = subprocess.run(["net", "accounts"], capture_output=True, text=True)
        output = result.stdout
        password_history = "Password history length: N/A"
        max_password_age = "Maximum password age: N/A days"
        min_password_length = "Minimum password length: N/A"

        for line in output.splitlines():
            if "Password history" in line:
                password_history = line.strip()
            if "Maximum password age" in line:
                max_password_age = line.strip()
            if "Minimum password length" in line:
                min_password_length = line.strip()

        print(f"[CHECK] {password_history} (should be >= 24)")
        print(f"[CHECK] {max_password_age} (should be <= 60)")
        print(f"[CHECK] {min_password_length} (should be >= 14)")
    except Exception as e:
        print(f"[ERROR] Unable to check password policy: {e}")

def check_uac():
    try:
        result = subprocess.run(["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA"], capture_output=True, text=True)
        if "0x1" in result.stdout:
            print("[PASS] UAC is enabled.")
        else:
            print("[FAIL] UAC is disabled.")
    except Exception as e:
        print(f"[ERROR] Unable to check UAC status: {e}")

def check_audit_policy():
    try:
        result = subprocess.run(["auditpol", "/get", "/category:*"], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("[ERROR] Unable to check audit policy.")
    except Exception as e:
        print(f"[ERROR] Unable to check audit policy: {e}")

def check_account_lockout_policy():
    try:
        result = subprocess.run(["net", "accounts"], capture_output=True, text=True)
        output = result.stdout
        lockout_threshold = "Account lockout threshold: N/A"
        lockout_duration = "Account lockout duration: N/A minutes"

        for line in output.splitlines():
            if "Lockout threshold" in line:
                lockout_threshold = line.strip()
            if "Lockout duration" in line:
                lockout_duration = line.strip()

        print(f"[CHECK] {lockout_threshold} (should be >= 3)")
        print(f"[CHECK] {lockout_duration} (should be >= 15)")
    except Exception as e:
        print(f"[ERROR] Unable to check account lockout policy: {e}")

def check_smbv1_status():
    try:
        result = subprocess.run(["powershell", "Get-WindowsOptionalFeature", "-Online", "-FeatureName", "SMB1Protocol"], capture_output=True, text=True)
        if "Disabled" in result.stdout:
            print("[PASS] SMBv1 is disabled.")
        else:
            print("[FAIL] SMBv1 is enabled.")
    except Exception as e:
        print(f"[ERROR] Unable to check SMBv1 status: {e}")

def check_remote_registry_service():
    try:
        result = subprocess.run(["sc", "query", "RemoteRegistry"], capture_output=True, text=True)
        if "STOPPED" in result.stdout:
            print("[PASS] Remote Registry service is disabled.")
        else:
            print("[FAIL] Remote Registry service is enabled.")
    except Exception as e:
        print(f"[ERROR] Unable to check Remote Registry service: {e}")

def main():
    print("=== Windows OS CIS Benchmark Compliance Check ===")
    print("\n=== Checking Firewall Status ===")
    check_firewall_status()

    print("\n=== Checking Windows Updates ===")
    check_windows_updates()

    print("\n=== Checking Password Policy ===")
    check_password_policy()

    print("\n=== Checking User Account Control (UAC) ===")
    check_uac()

    print("\n=== Checking Audit Policy ===")
    check_audit_policy()

    print("\n=== Checking Account Lockout Policy ===")
    check_account_lockout_policy()

    print("\n=== Checking Registry Settings ===")
    check_smbv1_status()

    print("\n=== Checking Service Configurations ===")
    check_remote_registry_service()

    print("\n=== CIS Benchmark Checks Completed ===")

if __name__ == "__main__":
    main()
