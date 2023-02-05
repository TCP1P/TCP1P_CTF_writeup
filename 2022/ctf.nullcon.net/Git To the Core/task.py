import os
import tempfile
import subprocess
import shutil

print("Challenge was created with <3 by @gehaxelt.")
git_url = input("Let's dump a .git/ repository from a web server of your choice. Please provide an URL: ")

uid = 1500 #cloner
gid = 65534 #nobody

temp_dir = tempfile.mkdtemp()
os.chown(temp_dir, uid, -1)

# https://stackoverflow.com/questions/2699907/dropping-root-permissions-in-python/2699996#2699996
os.setgroups([])
os.setgid(gid) #nobody
os.setuid(uid) #cloner

os.chdir(temp_dir)
print("Running command: ", ' '.join(["/opt/GitTools/Dumper/gitdumper.sh", git_url, "./repo"]))
clone_output = subprocess.run(["/opt/GitTools/Dumper/gitdumper.sh", git_url, "./repo"], capture_output=True, timeout=10, text=True)

print(clone_output.stdout)
print(clone_output.stderr)

if os.path.exists("./repo") and os.path.isdir("./repo"):
    os.chdir("./repo")
    print("Running git checkout: ", ' '.join(["git", "checkout", "."]))
    checkout_output = subprocess.run(["git", "checkout", "."], capture_output=True, timeout=10, text=True)
    print(checkout_output.stdout)
    print(checkout_output.stderr)
else:
    print("Failed to clone the repository!")

os.chdir(temp_dir)
shutil.rmtree(temp_dir)