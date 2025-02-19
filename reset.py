import shutil
import sys, os

if sys.argv[1] == "clone" and os.path.exists("./test_clone"):
    shutil.rmtree("test_clone")

os.mkdir("test_clone")
