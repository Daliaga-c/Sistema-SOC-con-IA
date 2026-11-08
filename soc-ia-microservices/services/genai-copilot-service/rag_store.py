import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

try:
    import numpy as np
except ImportError:  # pragma: no cover - fallback for minimal environments
    np = None


@dataclass
class RAGDocument:
    id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class LocalVectorStore:
    """Vector store local con embeddings deterministas para trabajar sin modelo externo.

    Esta implementación se aleja del enfoque totalmente semántico de Gemini + ChromaDB,
    pero mantiene la disciplina operativa del RAG: indexación, recuperación por similitud
    y soporte local para pruebas sin depender de un acceso externo.
    """

    def __init__(self, vector_size: int = 256, persist_directory: str | None = None):
        self.vector_size = vector_size
        self.persist_directory = Path(persist_directory or "./chroma_db")
        self.documents: List[RAGDocument] = []
        self.vectors: List[List[float]] = []
        self._load_from_disk()

    def _tokenize(self, text: str) -> List[str]:
        cleaned = ''.join(ch if ch.isalnum() or ch.isspace() else ' ' for ch in text.lower())
        return [token for token in cleaned.split() if token]

    def _embed_text(self, text: str) -> List[float]:
        tokens = self._tokenize(text)
        if not tokens:
            return [0.0 for _ in range(self.vector_size)]

        vector = [0.0 for _ in range(self.vector_size)]
        for token in tokens:
            digest = int(hashlib.sha1(token.encode('utf-8')).hexdigest(), 16)
            index = digest % self.vector_size
            vector[index] += 1.0

        norm = sum(v * v for v in vector) ** 0.5
        if norm == 0:
            return vector
        return [value / norm for value in vector]

    def _cosine_similarity(self, left: Sequence[float], right: Sequence[float]) -> float:
        if np is not None:
            left_arr = np.asarray(left, dtype=float)
            right_arr = np.asarray(right, dtype=float)
            denom = (np.linalg.norm(left_arr) * np.linalg.norm(right_arr))
            if denom == 0:
                return 0.0
            return float(np.dot(left_arr, right_arr) / denom)

        dot = sum(a * b for a, b in zip(left, right))
        left_norm = (sum(a * a for a in left) ** 0.5) or 1.0
        right_norm = (sum(b * b for b in right) ** 0.5) or 1.0
        if left_norm == 0 or right_norm == 0:
            return 0.0
        return dot / (left_norm * right_norm)

    def add_documents(self, documents: Iterable[RAGDocument]) -> None:
        for doc in documents:
            self.documents.append(doc)
            self.vectors.append(self._embed_text(doc.content))
        self._persist_to_disk()

    def search(self, query: str, limit: int = 3) -> List[Tuple[RAGDocument, float]]:
        query_vector = self._embed_text(query)
        scores = []
        for doc, vector in zip(self.documents, self.vectors):
            sim = self._cosine_similarity(query_vector, vector)
            scores.append((doc, sim))

        scores.sort(key=lambda item: item[1], reverse=True)
        return scores[:limit]

    def _persist_to_disk(self) -> None:
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "vector_size": self.vector_size,
            "documents": [
                {"id": doc.id, "content": doc.content, "metadata": doc.metadata}
                for doc in self.documents
            ],
        }
        with open(self.persist_directory / 'knowledge_base.json', 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)

    def _load_from_disk(self) -> None:
        file_path = self.persist_directory / 'knowledge_base.json'
        if not file_path.exists():
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as handle:
                payload = json.load(handle)
        except (json.JSONDecodeError, OSError):
            return

        for item in payload.get('documents', []):
            doc = RAGDocument(
                id=str(item.get('id', 'doc')),
                content=str(item.get('content', '')),
                metadata=item.get('metadata', {}),
            )
            self.documents.append(doc)
            self.vectors.append(self._embed_text(doc.content))


def build_default_knowledge() -> List[RAGDocument]:
    docs = [
        RAGDocument(
            id='nist-incident-handling',
            content=(
                'NIST SP 800-61 Rev 2: preparar, detectar, analizar, contener, erradicar, recuperar y aprender. '
                'Cuando hay uso indebido de credenciales, priorizar confirmación del usuario, aislar la cuenta, '
                'revisar sesiones activas y bloquear fuentes sospechosas con aprobación humana.'
            ),
            metadata={'source': 'NIST', 'theme': 'incident_response'}
        ),
        RAGDocument(
            id='mitre-t1110',
            content=(
                'MITRE ATT&CK T1110 Brute Force: el atacante intenta adivinar credenciales o probar combinaciones '
                'de usuario y contraseña. Recomendado bloquear IP, activar MFA, limitar intentos y revisar logs de '
                'autenticación para detectar patrones de fuerza bruta.'
            ),
            metadata={'source': 'MITRE', 'technique': 'T1110'}
        ),
        RAGDocument(
            id='mitre-t1078',
            content=(
                'MITRE ATT&CK T1078 Valid Accounts: adversarios reutilizan credenciales válidas, a menudo desde '
                'horarios inusuales o IPs no habituales. Se recomienda revisar sesión, revocar tokens, cambiar '
                'contraseñas y validar si la actividad corresponde a un usuario real.'
            ),
            metadata={'source': 'MITRE', 'technique': 'T1078'}
        ),
        RAGDocument(
            id='soc-hardening',
            content=(
                'Hardening SOC: aplicar MFA obligatorio, controles de sesión, monitorización de IPs anómalas, '
                'alertas sobre accesos en horas extrañas y orden de contención con sign-off humano.'
            ),
            metadata={'source': 'SOC', 'theme': 'hardening'}
        ),
    ]
    return docs


def ensure_default_index(persist_directory: str | None = None) -> LocalVectorStore:
    store = LocalVectorStore(persist_directory=persist_directory)
    if not store.documents:
        store.add_documents(build_default_knowledge())
    return store
