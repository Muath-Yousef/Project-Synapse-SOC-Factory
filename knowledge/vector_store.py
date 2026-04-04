import json
import yaml
import logging
import chromadb
from typing import List, Dict, Any
import os

logger = logging.getLogger(__name__)

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

    def query_context(self, collection_name: str, query_text: str, n_results: int = 1) -> List[str]:
        """
        Queries ChromaDB for semantic context matching the query_text.
        """
        collection = None
        if collection_name == "clients":
            collection = self.client_collection
        elif collection_name == "compliance":
            collection = self.compliance_collection
        else:
            logger.error(f"Unknown collection: {collection_name}")
            return []

        if collection.count() == 0:
            logger.warning(f"Collection '{collection_name}' is empty. Returning no context.")
            return []

        results = collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        
        # Results structure: {'documents': [['doc1', 'doc2']]}
        if results and "documents" in results and results["documents"]:
            if results["documents"][0]:
                return results["documents"][0]
                
        return []
