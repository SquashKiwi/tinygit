import shutil
import os

if os.path.exists("./test_clone"):
    shutil.rmtree("test_clone")

os.mkdir("test_clone")
