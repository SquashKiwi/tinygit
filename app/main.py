import hashlib
import sys
import os
import zlib


def main():
    
    print("custom git run", file=sys.stderr)

    command = sys.argv[1]
    if command == "init":
        os.mkdir(".git")
        os.mkdir(".git/objects")
        os.mkdir(".git/refs")
        flag = sys.argv[2]
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



                            
    else:
        raise RuntimeError(f"Unknown command #{command}")



if __name__ == "__main__":
    main()
