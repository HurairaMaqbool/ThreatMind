import hashlib


def stable_doc_id(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()
