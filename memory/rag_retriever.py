import os
from memory.chromadb_client import threat_reports_col, kql_library_col, sentinel_schema_col
from memory.embeddings import get_embedding

from rank_bm25 import BM25Okapi
import numpy as np


def reciprocal_rank_fusion(vector_results, keyword_results, top_k=3, k=60):
    scores = {}
    docs = {}

    for rank, doc in enumerate(vector_results):
        doc_id = doc["id"]
        scores[doc_id] = scores.get(doc_id, 0) + 1 / (k + rank + 1)
        docs[doc_id] = doc

    for rank, doc in enumerate(keyword_results):
        doc_id = doc["id"]
        scores[doc_id] = scores.get(doc_id, 0) + 1 / (k + rank + 1)
        docs[doc_id] = doc

    sorted_ids = sorted(scores.keys(), key=lambda i: scores[i], reverse=True)
    return [docs[i] for i in sorted_ids[:top_k]]


def vector_search(query_text: str, collection, top_k=5, where=None):
    if collection.count() == 0:
        return []
    res = collection.query(
        query_embeddings=[get_embedding(query_text[:2000])], where=where, n_results=top_k
    )
    out = []
    if res["documents"] and len(res["documents"]) > 0:
        for i in range(len(res["documents"][0])):
            out.append(
                {
                    "id": res["ids"][0][i],
                    "text": res["documents"][0][i],
                    "metadata": res["metadatas"][0][i],
                }
            )
    return out


def keyword_search(query_text: str, collection, top_k=5, where=None):
    if collection.count() == 0:
        return []
    all_data = collection.get(where=where)
    if not all_data or not all_data["documents"]:
        return []

    tokenized_corpus = [doc.split(" ") for doc in all_data["documents"]]
    bm25 = BM25Okapi(tokenized_corpus)
    tokenized_query = query_text.split(" ")
    doc_scores = bm25.get_scores(tokenized_query)

    top_n_idx = np.argsort(doc_scores)[::-1][:top_k]

    out = []
    for idx in top_n_idx:
        if doc_scores[idx] > 0:
            out.append(
                {
                    "id": all_data["ids"][idx],
                    "text": all_data["documents"][idx],
                    "metadata": all_data["metadatas"][idx],
                }
            )
    return out


def hybrid_search(query_text: str, iocs: dict, collection, top_k=3, where=None):
    vector_results = vector_search(query_text, collection, top_k=5, where=where)

    kw_query = query_text
    if iocs:
        for v in iocs.values():
            if isinstance(v, str):
                kw_query += f" {v}"
            elif isinstance(v, list):
                kw_query += f" {' '.join(str(x) for x in v)}"

    keyword_results = keyword_search(kw_query, collection, top_k=5, where=where)
    return reciprocal_rank_fusion(vector_results, keyword_results, top_k=top_k)


def find_similar_threats(text: str, iocs: dict, top_k: int = 3):
    return hybrid_search(text, iocs, threat_reports_col, top_k=top_k)


def find_historical_kql(behavior_description: str, iocs: dict, top_k: int = 3):
    schema_version = os.getenv("SCHEMA_VERSION", "v3")
    where = {"schema_version": schema_version}
    return hybrid_search(behavior_description, iocs, kql_library_col, top_k=top_k, where=where)


def get_table_schema_snippet(table_name: str, detection_idea: str, top_k: int = 5):
    if sentinel_schema_col.count() == 0:
        return []

    query_text = f"{table_name} {detection_idea}"

    results = sentinel_schema_col.query(
        query_embeddings=[get_embedding(query_text)],
        where={"table_name": table_name},
        n_results=top_k,
    )

    columns = []
    if results["documents"] and len(results["documents"]) > 0:
        for i in range(len(results["documents"][0])):
            meta = results["metadatas"][0][i]
            columns.append(
                {
                    "column": meta["column_name"],
                    "type": meta["data_type"],
                    "desc": meta["description"],
                }
            )
    return columns
