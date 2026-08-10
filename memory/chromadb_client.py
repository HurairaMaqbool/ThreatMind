import os
import yaml
import chromadb
from memory.embeddings import get_embedding
from utils.ids import stable_doc_id

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chroma_db")
client = chromadb.PersistentClient(path=DB_DIR)

threat_reports_col = client.get_or_create_collection("threat_reports")
kql_library_col = client.get_or_create_collection("kql_library")
processed_urls_col = client.get_or_create_collection("processed_urls")
sentinel_schema_col = client.get_or_create_collection("sentinel_schema")


def init_schema_if_empty():
    if sentinel_schema_col.count() > 0:
        return

    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config", "sentinel_schema.yaml"
    )
    if not os.path.exists(schema_path):
        print(f"Warning: Schema file not found at {schema_path}")
        return

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_data = yaml.safe_load(f)

    print("Populating 'sentinel_schema' collection for the first time...")

    ids, documents, metadatas = [], [], []

    for table_name, columns in schema_data.items():
        for col_str in columns:
            if isinstance(col_str, dict):
                col_info = list(col_str.keys())[0].strip("- ")
                description = str(list(col_str.values())[0]).strip()
            else:
                col_parts = str(col_str).split(":", 1)
                if len(col_parts) == 2:
                    col_info = col_parts[0].strip("- ")
                    description = col_parts[1].strip()
                else:
                    continue

            name_type = col_info.split(" (")
            col_name = name_type[0].strip()
            data_type = name_type[1].replace(")", "").strip() if len(name_type) > 1 else "string"
            doc_text = f"{table_name} {col_name} {description}"

            ids.append(f"{table_name}_{col_name}")
            documents.append(doc_text)
            metadatas.append(
                {
                    "table_name": table_name,
                    "column_name": col_name,
                    "data_type": data_type,
                    "description": description,
                }
            )

    for i in range(len(ids)):
        sentinel_schema_col.add(
            ids=[ids[i]],
            documents=[documents[i]],
            embeddings=[get_embedding(documents[i])],
            metadatas=[metadatas[i]],
        )

    print(f"Schema collection populated with {len(ids)} columns.")


init_schema_if_empty()


def store_threat_report(url: str, text: str, metadata: dict):
    doc_id = metadata.get("threat_id") or stable_doc_id(url)
    metadata = {**metadata, "url": url}
    threat_reports_col.upsert(
        ids=[doc_id],
        documents=[text],
        embeddings=[get_embedding(text)],
        metadatas=[metadata],
    )


def store_kql_query(angle_id: str, kql: str, score: int, behavior_description: str, metadata: dict):
    schema_version = os.getenv("SCHEMA_VERSION", "v3")
    metadata["schema_version"] = schema_version
    metadata["prompt_version"] = schema_version
    metadata.setdefault("sigma_rule", "")
    metadata.setdefault("multiplatform_queries", "{}")
    metadata.setdefault("evasion_notes", "")
    metadata["score"] = str(score)

    kql_library_col.upsert(
        ids=[angle_id],
        documents=[kql],
        embeddings=[get_embedding(behavior_description)],
        metadatas=[metadata],
    )


def mark_old_queries_as_legacy():
    results = kql_library_col.get()
    if not results or not results["ids"]:
        return

    ids_to_update, metadatas_to_update = [], []
    for i in range(len(results["ids"])):
        meta = results["metadatas"][i] or {}
        if "schema_version" not in meta:
            meta["schema_version"] = "legacy"
            meta["prompt_version"] = "legacy"
            ids_to_update.append(results["ids"][i])
            metadatas_to_update.append(meta)

    if ids_to_update:
        kql_library_col.update(ids=ids_to_update, metadatas=metadatas_to_update)
        print(f"Migrated {len(ids_to_update)} legacy KQL queries.")


mark_old_queries_as_legacy()


def get_kql_library_size() -> int:
    return kql_library_col.count()


def get_threat_by_id(threat_id: str) -> dict | None:
    try:
        results = threat_reports_col.get(ids=[threat_id])
        if results and results["ids"]:
            return {
                "id": results["ids"][0],
                "document": results["documents"][0] if results["documents"] else "",
                "metadata": results["metadatas"][0] if results["metadatas"] else {},
            }
    except Exception:
        pass

    try:
        all_results = threat_reports_col.get()
        if not all_results or not all_results["ids"]:
            return None
        for i, meta in enumerate(all_results.get("metadatas", []) or []):
            if meta and meta.get("threat_id") == threat_id:
                return {
                    "id": all_results["ids"][i],
                    "document": all_results["documents"][i] if all_results["documents"] else "",
                    "metadata": meta,
                }
    except Exception:
        return None
    return None


def get_latest_threat() -> dict | None:
    try:
        results = threat_reports_col.get()
        if not results or not results["ids"]:
            return None
        metadatas = results["metadatas"]
        if not metadatas:
            return None
        sorted_metas = sorted(metadatas, key=lambda x: x.get("date", ""), reverse=True)
        return sorted_metas[0]
    except Exception as e:
        import logging
        logging.error(f"Error connecting to ChromaDB: {e}")
        return None


def search_similar_threats(query: str, n_results: int = 3) -> list:
    try:
        results = threat_reports_col.query(
            query_embeddings=[get_embedding(query)],
            n_results=n_results,
        )
        if not results or not results["ids"] or not results["ids"][0]:
            return []

        threats = []
        for i in range(len(results["ids"][0])):
            threats.append(
                {
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i] if results["documents"] else "",
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                }
            )
        return threats
    except Exception as e:
        import logging
        logging.error(f"Error searching similar threats: {e}")
        return []


def search_similar_kql(query: str, n_results: int = 3) -> list:
    try:
        results = kql_library_col.query(
            query_embeddings=[get_embedding(query)],
            n_results=n_results,
        )
        if not results or not results["ids"] or not results["ids"][0]:
            return []

        kqls = []
        for i in range(len(results["ids"][0])):
            kqls.append(
                {
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i] if results["documents"] else "",
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                }
            )
        return kqls
    except Exception as e:
        import logging
        logging.error(f"Error searching similar KQL: {e}")
        return []
