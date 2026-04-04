import json
import yaml
import logging
import chromadb
from typing import List, Dict, Any
import os

logger = logging.getLogger(__name__)

class ClientProfileNotFoundError(Exception):
    """Exception raised when a client profile is not found in the vector store."""
    pass

class VectorStore:
    """
    Manages the ChromaDB instance for storing and retrieving context
    such as Client Profiles and Compliance Controls.
    Provides RAG-ready context to the LLM.
    """
    def __init__(self, persist_dir: str = ".chroma_db"):
        self.persist_dir = persist_dir
        # Initialize persistent ChromaDB client
        self.client = chromadb.PersistentClient(path=self.persist_dir)
        
        # Get or create collections
        self.client_collection = self.client.get_or_create_collection(name="clients")
        self.compliance_collection = self.client.get_or_create_collection(name="compliance")
        
        logger.info(f"Initialized VectorStore at {self.persist_dir}")

    def ingest_client_profile(self, yaml_path: str):
        """
        Reads a client profile YAML and ingests its context into ChromaDB.
        """
        if not os.path.exists(yaml_path):
            logger.error(f"Client profile {yaml_path} not found.")
            return

        with open(yaml_path, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
            
        client_name = data.get("client_name", os.path.basename(yaml_path))
        
        # Flatten YAML to textual representation so semantic search works best
        text_content = yaml.dump(data, allow_unicode=True)
        
        self.client_collection.upsert(
            documents=[text_content],
            metadatas=[{"client_name": client_name, "type": "profile"}],
            ids=[f"client_profile_{client_name.lower().replace(' ', '_')}"]
        )
        logger.info(f"Ingested Client Profile: {client_name}")

    def ingest_compliance_framework(self, json_path: str):
        """
        Reads a compliance framework JSON and ingests each control into ChromaDB.
        """
        if not os.path.exists(json_path):
            logger.error(f"Compliance framework {json_path} not found.")
            return

        with open(json_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            
        framework_name = data.get("framework", "Unknown Framework")
        controls = data.get("controls", [])
        
        documents = []
        metadatas = []
        ids = []
        
        for control in controls:
            control_id = control.get("id", "")
            title = control.get("title", "")
            desc = control.get("description", "")
            
            doc_text = f"Control ID: {control_id}\nTitle: {title}\nDescription: {desc}"
            
            documents.append(doc_text)
            metadatas.append({"framework": framework_name, "control_id": control_id})
            ids.append(f"compliance_{framework_name}_{control_id}".lower().replace(' ', '_'))
            
        if documents:
            self.compliance_collection.upsert(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            logger.info(f"Ingested {len(documents)} controls for {framework_name}")

    def query_context(self, collection_name: str, query_text: str, n_results: int = 1, client_id: str = None) -> Dict[str, Any]:
        """
        Queries ChromaDB for semantic context matching the query_text.
        If client_id is provided, applies a strict metadata filter.
        Always returns a dictionary (parsed YAML or wrapped text).
        """
        collection = None
        if collection_name == "clients":
            collection = self.client_collection
        elif collection_name == "compliance":
            collection = self.compliance_collection
        else:
            logger.error(f"Unknown collection: {collection_name}")
            return {"status": "error", "message": f"Unknown collection: {collection_name}"}

        # Case 1: Client profile search must verify it's onboarded
        if client_id and collection_name == "clients":
            count = collection.count()
            if count == 0:
                raise ClientProfileNotFoundError(f"No clients onboarded in '{collection_name}' collection.")
            
            check = collection.get(where={"client_name": {"$eq": client_id}})
            if not check or not check["ids"]:
                raise ClientProfileNotFoundError(f"Client '{client_id}' not found in '{collection_name}' collection.")

        if collection.count() == 0:
            return {"status": "empty", "message": f"Collection '{collection_name}' is empty."}

        # Prepare filter
        where_filter = None
        if client_id:
            where_filter = {"client_name": {"$eq": client_id}}

        results = collection.query(
            query_texts=[query_text],
            n_results=n_results,
            where=where_filter
        )
        
        # Results structure: {'documents': [['doc1', 'doc2']]}
        if results and "documents" in results and results["documents"] and results["documents"][0]:
            raw_doc = results["documents"][0][0]
            try:
                # Attempt to parse as YAML
                parsed = yaml.safe_load(raw_doc)
                if isinstance(parsed, dict):
                    parsed["status"] = "success"
                    return parsed
                else:
                    # Not a dict after parsing, wrap it
                    return {"status": "success", "client_name": client_id, "content": raw_doc}
            except Exception:
                # Parsing failed, return as raw context
                return {"status": "success", "client_name": client_id, "content": raw_doc}
                
        return {"status": "not_found", "message": "No matching context found."}
