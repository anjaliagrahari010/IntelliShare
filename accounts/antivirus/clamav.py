import subprocess
import os
import shutil

# Automatically find ClamAV from system PATH
CLAMSCAN_PATH = shutil.which("clamscan")


def scan_file(file_path):

    # Check file exists
    if not os.path.exists(file_path):
        return False, "File to scan does not exist."

    # Check ClamAV exists
    if not CLAMSCAN_PATH:
        return False, "ClamAV scanner is not installed."

    try:
        result = subprocess.run(
            [
                CLAMSCAN_PATH,
                "--no-summary",
                file_path
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        print("ClamAV Path:", CLAMSCAN_PATH)
        print("ClamAV Return Code:", result.returncode)
        print("ClamAV Output:", result.stdout)
        print("ClamAV Error:", result.stderr)

        # Return code 0 = clean
        if result.returncode == 0:
            return True, "File is clean."

        # Return code 1 = malware found
        elif result.returncode == 1:
            return False, "Malware detected in the uploaded file."

        # Return code 2 or anything else = scanner problem
        else:
            error_message = result.stderr or result.stdout
            return False, f"ClamAV scanning failed: {error_message}"

    except subprocess.TimeoutExpired:
        return False, "Malware scan timed out. Upload blocked."

    except Exception as e:
        print("ClamAV Exception:", str(e))
        return False, f"Unable to scan the file: {str(e)}"