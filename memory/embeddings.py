import os
from sentence_transformers import SentenceTransformer

# Load embedding model once to prevent memory overhead
# all-MiniLM-L6-v2 is fast, lightweight, and perfect for generic text similarity
MODEL_NAME = "all-MiniLM-L6-v2"

print(f"Loading embedding model {MODEL_NAME}...")
embedding_model = SentenceTransformer(MODEL_NAME)

def get_embedding(text: str) -> list[float]:
    """
    Converts a string of text into a vector of numbers (embedding).
    """
    if not text:
        return []
    
    # Encode returns a numpy array, convert to standard python list for ChromaDB
    vector = embedding_model.encode(text)
    return vector.tolist()

def get_embeddings(texts: list[str]) -> list[list[float]]:
    """
    Batch encodes multiple strings into vectors.
    """
    if not texts:
        return []
        
    vectors = embedding_model.encode(texts)
    return [v.tolist() for v in vectors]
