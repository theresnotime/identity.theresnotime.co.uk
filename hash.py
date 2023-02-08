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


def save_hash(filename, hash):
    with open(f"public/{filename}.sha256.txt", "w") as f:
        f.write(hash)


if __name__ == "__main__":
    save_hash(config.INDEX_FILE, hash_file(config.INDEX_FILE))
    save_hash(config.KEYBASE_FILE, hash_file(config.KEYBASE_FILE))
