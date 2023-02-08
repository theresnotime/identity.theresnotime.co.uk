import hashlib
import config


def hash_file(filename):
    """Generate a SHA256 hash of a file"""
    file_hash = hashlib.sha256()
    with open(f"public/{filename}", "rb") as f:
        fb = f.read(config.BLOCK_SIZE)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(config.BLOCK_SIZE)
    return file_hash.hexdigest()


def check_hash(filename, hash):
    with open(f"public/{filename}.sha256.txt", "r") as f:
        read_hash = f.read()
        print(f"[{filename}]: Read {read_hash}")
        print(f"[{filename}]: Calc {hash}")
        if read_hash == hash:
            print(f"[{filename}]: Hashes match")
            return True
        else:
            raise Exception(f"[{filename}]: Hash mismatch")


if __name__ == "__main__":
    index_hash = check_hash(
        config.INDEX_FILE,
        hash_file(config.INDEX_FILE)
    )
    keybase_hash = check_hash(
        config.KEYBASE_FILE,
        hash_file(config.KEYBASE_FILE)
    )
    if index_hash and keybase_hash:
        print("All hashes match")
