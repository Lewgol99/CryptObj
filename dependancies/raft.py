import subprocess
import sys

def install_pip():
    try:
        subprocess.run(["apt", "update"])  # Update package lists
        subprocess.run(["apt", "install", "-y", "python3-pip"])  # Install pip for Python 3
        subprocess.run(["apt", "install", "-y", "lftp"])  # Install ftp
        print("pip and ftp installed successfully.")
    except Exception as e:
        print(f"Error installing pip: {e}")
        sys.exit(1)  # Exit the script if installation fails

def git_clone(repository_url):
    try:
        subprocess.run(["git", "clone", repository_url])  # Clone the repository to the current directory
        print(f"Repository cloned successfully.")
    except Exception as e:
        print(f"Error cloning repository: {e}")
        sys.exit(1)  # Exit the script if cloning fails

def install_dependencies():
    try:
        subprocess.run(["pip", "install", "web3==4.9.2"])  # Install the 'web3' library
        subprocess.run(["pip", "install", "--upgrade" "web3"])  # Install the upgrade
        subprocess.run(["pip", "install", "lxml"])  # Install the 'lxml' library
        subprocess.run(["pip", "install", "pysyncobj"])  # Install the 'pysyncobj' library
        subprocess.run(["pip", "install", "watchdog"])  # Install the 'watchdog' library
        subprocess.run(["pip", "install", "requests"])  # Install the 'requests' library
        subprocess.run(["pip", "install", "dill"])  # Install the 'dill' library
        subprocess.run(["pip", "install", "psutil"])  # Install psutil library
        subprocess.run(["pip", "install", "colorama"])  # Install colorama library
        subprocess.run(["pip3", "install", "pandas"])  # Install psutil library
        subprocess.run(["pip3", "install", "cryptography"])  # Install cryptography library
        subprocess.run(["pip3", "install", "flask"])  # Install flask library
        print("Dependencies installed successfully.")
    except Exception as e:
        print(f"Error installing dependencies: {e}")
        sys.exit(1)  # Exit the script if installation fails

if __name__ == "__main__":
    install_pip()  # Install pip if not already installed
    git_clone("https://github.com/bakwc/PySyncObj.git")  # Clone PySyncObj repository using git protocol
    install_dependencies()  # Install Python dependencies
