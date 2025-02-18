import hashlib
import sys
import os
import zlib
from pathlib import Path

def write_blob(sha1, store, write=True):
    
    if write:
        dir_path = f".git/objects/{sha1[:2]}"
        file_path = f"{dir_path}/{sha1[2:]}"
        os.makedirs(dir_path, exist_ok=True)
        compressed_content = zlib.compress(store)
        with open(file_path, 'wb') as blob:
            blob.write(compressed_content)

    return sha1


def write_tree(path):
    contents = sorted(
        os.listdir(path),
        key=lambda x: x if os.path.isfile(os.path.join(path, x)) else f"{x}/",
    )

    s = b""
    for item in contents:
        full = os.path.join(path, item)
        if ".git" in item:
            continue
        elif os.path.isfile(full):
            with open(full, 'rb') as f:
                content = f.read()
            header = f"blob {len(content)}\0".encode("utf-8")
            store = header + content
            sha1 = hashlib.sha1(store).hexdigest()
            write_blob(sha1, store)
            s += f"100644 {item}\0".encode() + bytes.fromhex(sha1)
        else:
            sha1 = write_tree(full)
            s += f"40000 {item}\0".encode() + bytes.fromhex(sha1)
    
    s = f"tree {len(s)}\0".encode() + s
    sha1 = hashlib.sha1(s).hexdigest()
    dir_path = f".git/objects/{sha1[:2]}"
    file_path = f"{dir_path}/{sha1[2:]}"
    os.makedirs(dir_path, exist_ok=True)
    compressed_content = zlib.compress(s)
    with open(file_path, 'wb') as blob:
        blob.write(compressed_content)

    return sha1            


def ls_tree():
    flag = sys.argv[2]
    file_hash = flag
    if len(flag) < 10:
        flag = None
    else:
        file_hash = sys.argv[3]
    file_path = f".git/objects/{file_hash[:2]}/{file_hash[2:]}"
    
    with open(file_path, "rb") as file:
        contents = zlib.decompress(file.read())
        _, binary = contents.split(b"\x00", maxsplit=1)
        
        while binary:
            mode, binary = binary.split(b" ", maxsplit=1)
            name, binary = binary.split(b"\x00", maxsplit=1)
            sha1 = binary[:20]
            binary = binary[20:]
            
            # Convert binary SHA1 to hex string and print with name
            sha1_hex = ''.join('{:02x}'.format(byte) for byte in sha1) if not flag else ""
            print(f"{name.decode()} {sha1_hex}")


def main():
    
    print("TinyGit Running...", file=sys.stderr)

    command = sys.argv[1]

    if command != "init" and not os.path.isdir(".git"):
        print("Error: not a git repository (or any of the parent directories): .git", file=sys.stderr)
        sys.exit(1)

    if command == "init":
        os.mkdir(".git")
        os.mkdir(".git/objects")
        os.mkdir(".git/refs") 
        with open(".git/HEAD", "w") as f:
            f.write("ref: refs/heads/main\n")
        print("Initialized git directory")
    
    

    elif command == "cat-file":
        flag = sys.argv[2]
        if flag != '-p': 
            raise RuntimeError("only -p flag allowed") 
        hash = str(sys.argv[3])

        try:
            with open(f".git/objects/{hash[:2]}/{hash[2:]}", 'rb') as file:
                header, content = zlib.decompress(file.read()).decode().split("\0", maxsplit=1)
                print(content, end="")

        except FileNotFoundError:
            print(f"Error: object {hash} not found", file=sys.stderr)



    elif command == "hash-object":
        flag = sys.argv[2]
        if flag != '-w': 
            raise RuntimeError("only -w flag allowed") 
        filename = sys.argv[3]

        with open(filename, 'rb') as f:
            content = f.read()
        length = len(content)
        header = f"blob {length}\0".encode()
        store = header + content
        sha1Hash = hashlib.sha1(store).hexdigest()
        compressed_content = zlib.compress(store)
        
        dir_path = f".git/objects/{sha1Hash[:2]}"
        file_path = f"{dir_path}/{sha1Hash[2:]}"
        os.makedirs(dir_path, exist_ok=True)

        with open(file_path, 'wb') as blob:
            blob.write(compressed_content)
        print(sha1Hash)


    elif command == "ls-tree":
        ls_tree()

    elif command == "write-tree":
        # This assumes all files in directory are staged
        print(write_tree(os.path.curdir))
        
                            
    else:
        raise RuntimeError(f"Unknown command #{command}")



if __name__ == "__main__":
    main()
