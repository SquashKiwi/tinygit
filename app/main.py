import hashlib
import sys
import os
import zlib
from pathlib import Path
import time
from datetime import timezone, datetime
import urllib.request
from typing import Tuple, List, cast
import struct

DEV_MODE = False

def init_repo(parent):
    try:
        os.mkdir(f"{parent}/.git")
        os.mkdir(f"{parent}/.git/objects")
        os.mkdir(f"{parent}/.git/refs") 
        with open(f"{parent}/.git/HEAD", "w") as f:
            f.write("ref: refs/heads/main\n")
        print("Initialized git directory")
    except FileExistsError:
        print(f"Error: there is an existing git repository here. Path: {parent}")
        exit(1)


def write_blob(sha1, store, write=True):

    dir_path = f".git/objects/{sha1[:2]}"
    file_path = f"{dir_path}/{sha1[2:]}"
    os.makedirs(dir_path, exist_ok=True)
    compressed_content = zlib.compress(store)
    with open(file_path, 'wb') as blob:
        blob.write(compressed_content)

    return sha1

def write_object(parent: Path, ty: str, content: bytes) -> str:
    content = ty.encode() + b" " + f"{len(content)}".encode() + b"\0" + content
    hash = hashlib.sha1(content, usedforsecurity=False).hexdigest()
    compressed_content = zlib.compress(content)
    pre = hash[:2]
    post = hash[2:]
    p = parent / ".git" / "objects" / pre / post
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(compressed_content)
    return hash


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

def read_object(parent: Path, sha: str) -> Tuple[str, bytes]:
    pre = sha[:2]
    post = sha[2:]
    p = parent / ".git" / "objects" / pre / post
    bs = p.read_bytes()
    head, content = zlib.decompress(bs).split(b"\0", maxsplit=1)
    ty, _ = head.split(b" ")
    return ty.decode(), content

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


def commit_tree():
    args = sys.argv[2:]
    # print(args)
    tree_sha = args[0]
    if '-p' in args:
        commit_sha = args[2]
        message = args[4]
    else:
        try:
            message = args[2]
        except IndexError:
            print("commit message cannot be empty")
            exit(1)
        
    
    content = b"tree %b\n" % tree_sha.encode()
    
    if '-p' in args:
        content += b"parent %b\n" % commit_sha.encode()

    content += b''.join(
        [   b"author abc <example@gmail.com>" + f" {int(time.time())} {datetime.now().astimezone().strftime('%z')}\n\n".encode(),
            b"committer abc <example@gmail.com>" + f" {int(time.time())} {datetime.now().astimezone().strftime('%z')}\n\n".encode(),
            message.encode(),
            b"\n",
        ])
    # print(content)

    hash = write_object(Path("."), "commit", content)
    print(hash)


def main():
    
    print("TinyGit Running...", file=sys.stderr)

    command = sys.argv[1]

    if command != "init" and not os.path.isdir(".git") and not DEV_MODE:
        print("Error: not a git repository (or any of the parent directories): .git", file=sys.stderr)
        sys.exit(1)

    if command == "init":
        parent = '.'
        if len(sys.argv) > 2:
            parent = sys.argv[2]
        init_repo(parent)    

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

        print(write_blob(sha1Hash, store))
        # compressed_content = zlib.compress(store)
        
        # dir_path = f".git/objects/{sha1Hash[:2]}"
        # file_path = f"{dir_path}/{sha1Hash[2:]}"
        # os.makedirs(dir_path, exist_ok=True)

        # with open(file_path, 'wb') as blob:
        #     blob.write(compressed_content)
        # print(sha1Hash)

    elif command == "ls-tree":
        ls_tree()

    elif command == "write-tree":
        # This assumes all files in directory are staged
        print(write_tree(os.path.curdir))

    elif command == "commit-tree":
        commit_tree()

    elif command == "clone":
        parent = Path('.')
        arg_length = len(sys.argv)
        
        if arg_length < 3:
            print("Error: no URL provided")
            exit(1)

        url = sys.argv[2]

        if arg_length > 3:
            parent = sys.argv[3]

        print("Initializing repository...")
        init_repo(parent)
        
        print(f"Cloning from {url}...")
        try:
            req = urllib.request.Request(f"{url}/info/refs?service=git-upload-pack")
            with urllib.request.urlopen(req) as f:
                refs = {
                    bs[1].decode(): bs[0].decode()
                    for bs0 in cast(bytes, f.read()).split(b"\n")
                    if (bs1 := bs0[4:])
                    and not bs1.startswith(b"#")
                    and (bs2 := bs1.split(b"\0")[0])
                    and (bs := (bs2[4:] if bs2.endswith(b"HEAD") else bs2).split(b" "))
                }
        except urllib.error.URLError as e:
            print(f"Error connecting to repository: {e}")
            exit(1)
        print("Fetching repository information... done")
        print(f"Remote contains {len(refs)} refs")
        
        print("Setting up local refs...")
        for name, sha in refs.items():
            ref_path = Path(parent) / ".git" / name
            ref_path.parent.mkdir(parents=True, exist_ok=True)
            ref_path.write_text(sha + "\n")
        print("Local refs are set up.")
        
        body = (
                b"0011command=fetch0001000fno-progress"
                + b"".join(b"0032want " + ref.encode() + b"\n" for ref in refs.values())
                + b"0009done\n0000"
            )
        
        req = urllib.request.Request(
                f"{url}/git-upload-pack",
                data=body,
                headers={"Git-Protocol": "version=2"},
            )
        
        print("Downloading pack file...", end="", flush=True)
        with urllib.request.urlopen(req) as f:
            pack_bytes = cast(bytes, f.read())
        print(f" received {len(pack_bytes):,} bytes")
        
        # Break pack data into lines
        pack_lines = []
        while pack_bytes:
            line_len = int(pack_bytes[:4], 16)
            if line_len == 0:
                break
            pack_lines.append(pack_bytes[4:line_len])
            pack_bytes = pack_bytes[line_len:]
        pack_file = b"".join(l[1:] for l in pack_lines[1:])
        
        def next_size_type(bs: bytes) -> Tuple[str, int, bytes]:
            ty = (bs[0] & 0b_0111_0000) >> 4
            match ty:
                case 1:
                    ty = "commit"
                case 2:
                    ty = "tree"
                case 3:
                    ty = "blob"
                case 4:
                    ty = "tag"
                case 6:
                    ty = "ofs_delta"
                case 7:
                    ty = "ref_delta"
                case _:
                    ty = "unknown"
            size = bs[0] & 0b_0000_1111
            i = 1
            off = 4
            while bs[i - 1] & 0b_1000_0000:
                size += (bs[i] & 0b_0111_1111) << off
                off += 7
                i += 1
            return ty, size, bs[i:]
        
        def next_size(bs: bytes) -> Tuple[int, bytes]:
            size = bs[0] & 0b_0111_1111
            i = 1
            off = 7
            while bs[i - 1] & 0b_1000_0000:
                size += (bs[i] & 0b_0111_1111) << off
                off += 7
                i += 1
            return size, bs[i:]
        
        # Strip pack header and version
        pack_file = pack_file[8:]
        n_objs, *_ = struct.unpack("!I", pack_file[:4])
        pack_file = pack_file[4:]
        print(f"Pack file contains {n_objs} objects")
        
        # Process pack objects with progress display
        for idx in range(n_objs):
            if idx % 10 == 0:
                print(f"\rProcessing objects... {idx}/{n_objs}", end="", flush=True)
            ty, _, pack_file = next_size_type(pack_file)
            match ty:
                case "commit" | "tree" | "blob" | "tag":
                    dec = zlib.decompressobj()
                    content = dec.decompress(pack_file)
                    pack_file = dec.unused_data
                    write_object(parent, ty, content)
                case "ref_delta":
                    obj = pack_file[:20].hex()
                    pack_file = pack_file[20:]
                    dec = zlib.decompressobj()
                    content = dec.decompress(pack_file)
                    pack_file = dec.unused_data
                    target_content = b""
                    base_ty, base_content = read_object(parent, obj)
                    # Skip base and output sizes
                    _, content = next_size(content)
                    _, content = next_size(content)
                    while content:
                        is_copy = content[0] & 0b_1000_0000
                        if is_copy:
                            data_ptr = 1
                            offset = 0
                            size = 0
                            for i in range(0, 4):
                                if content[0] & (1 << i):
                                    offset |= content[data_ptr] << (i * 8)
                                    data_ptr += 1
                            for i in range(0, 3):
                                if content[0] & (1 << (4 + i)):
                                    size |= content[data_ptr] << (i * 8)
                                    data_ptr += 1
                            content = content[data_ptr:]
                            target_content += base_content[offset : offset + size]
                        else:
                            size = content[0]
                            append = content[1 : size + 1]
                            content = content[size + 1 :]
                            target_content += append
                    write_object(parent, base_ty, target_content)
                case _:
                    raise RuntimeError("Not implemented")
        print("\rProcessing objects... done" + " " * 20)
        
        # Render the working tree
        def render_tree(parent: Path, dir: Path, sha: str):
            dir.mkdir(parents=True, exist_ok=True)
            _, tree = read_object(parent, sha)
            while tree:
                mode, tree = tree.split(b" ", 1)
                name, tree = tree.split(b"\0", 1)
                sha = tree[:20].hex()
                tree = tree[20:]
                match mode:
                    case b"40000":
                        render_tree(parent, dir / name.decode(), sha)
                    case b"100644":
                        _, content = read_object(parent, sha)
                        Path(dir / name.decode()).write_bytes(content)
                    case _:
                        raise RuntimeError("Not implemented")
        
        _, commit = read_object(parent, refs["HEAD"])
        tree_sha = commit[5 : 40 + 5].decode()
        render_tree(parent, parent, tree_sha)
        
        print(f"Successfully cloned {url.split('/')[-1]}")
                            
    else:
        raise RuntimeError(f"Unknown command #{command}")



if __name__ == "__main__":
    main()
