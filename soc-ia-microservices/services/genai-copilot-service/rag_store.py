"""Almacén Vectorial Local y Base de Conocimiento RAG para el SOC Copilot.

Provee almacenamiento de embeddings deterministas, indexación de playbooks y guías
NIST / MITRE ATT&CK tanto estáticos como cargados dinámicamente desde el corpus Markdown.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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

    Mantiene la disciplina operativa del RAG: indexación, recuperación por similitud
    y soporte local para pruebas y ejecución autónoma.
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

    def rebuild(self, documents: Iterable[RAGDocument]) -> None:
        """Limpia la base y re-indexa completamente los documentos dados."""
        self.documents = []
        self.vectors = []
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

        self.documents = []
        self.vectors = []
        for item in payload.get('documents', []):
            doc = RAGDocument(
                id=str(item.get('id', 'doc')),
                content=str(item.get('content', '')),
                metadata=item.get('metadata', {}),
            )
            self.documents.append(doc)
            self.vectors.append(self._embed_text(doc.content))


def find_corpus_dir(custom_path: str | Path | None = None) -> Path | None:
    """Resuelve la ruta absoluta del directorio de corpus."""
    if custom_path:
        p = Path(custom_path)
        if p.is_dir():
            return p
    candidates = [
        Path(__file__).resolve().parent / "corpus",
        Path.cwd() / "soc-ia-microservices" / "services" / "genai-copilot-service" / "corpus",
        Path.cwd() / "corpus",
        Path(r"c:\Users\diego\Documents\Documentos\Inteligencia Artificial\soc-ia-microservices\services\genai-copilot-service\corpus"),
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def load_corpus_documents(corpus_dir: str | Path | None = None) -> List[RAGDocument]:
    """Carga y particiona en secciones semánticas todos los archivos Markdown del corpus."""
    target_dir = find_corpus_dir(corpus_dir)
    if not target_dir:
        return []

    docs: List[RAGDocument] = []
    technique_pattern = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')

    for md_file in sorted(target_dir.glob("*.md")):
        try:
            text = md_file.read_text(encoding="utf-8")
        except Exception:
            continue

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        doc_title = lines[0].lstrip("#").strip() if lines else md_file.stem

        # Dividir por encabezados de sección de segundo nivel (##)
        sections = re.split(r'\n(?=##\s+)', text)
        for idx, section in enumerate(sections):
            sec_clean = section.strip()
            if not sec_clean:
                continue

            sec_lines = [l.strip() for l in sec_clean.splitlines() if l.strip()]
            sec_header = sec_lines[0].lstrip("#").strip() if sec_lines else f"Sección {idx}"

            # Omitir sección cero si únicamente contiene el título del documento
            if idx == 0 and len(sec_lines) <= 2 and sec_lines[0].startswith("# "):
                continue

            # Determinación de fuente
            lower_name = md_file.name.lower()
            if "nist" in lower_name:
                source = "NIST"
            elif "mitre" in lower_name:
                source = "MITRE"
            elif "playbook" in lower_name or "wazuh" in lower_name:
                source = "SOC_PLAYBOOK"
            else:
                source = "SOC"

            # Detección de técnicas MITRE
            tech_matches = technique_pattern.findall(sec_clean)
            technique = ", ".join(sorted(list(set(tech_matches)))) if tech_matches else ""

            clean_stem = re.sub(r'[^a-zA-Z0-9_-]', '_', md_file.stem)
            doc_id = f"{clean_stem}-s{idx}"

            # Contenido enriquecido con metacontexto del documento
            enriched_content = f"[{doc_title}] - {sec_header}\n\n{sec_clean}"

            metadata = {
                "source": source,
                "filename": md_file.name,
                "section": sec_header,
                "document_title": doc_title,
            }
            if technique:
                metadata["technique"] = technique

            docs.append(RAGDocument(id=doc_id, content=enriched_content, metadata=metadata))

    return docs


def build_default_knowledge(corpus_dir: str | Path | None = None) -> List[RAGDocument]:
    """Compila la base de conocimiento completa: documentos nucleares base + corpus Markdown."""
    base_docs = [
        RAGDocument(
            id='nist-incident-handling',
            content=(
                'NIST SP 800-61 Rev 2: preparar, detectar, analizar, contener, erradicar, recuperar y aprender. '
                'Cuando hay uso indebido de credenciales, priorizar confirmación del usuario, aislar la cuenta, '
                'revisar sesiones activas y bloquear fuentes sospechosas con aprobación humana.'
            ),
            metadata={'source': 'NIST', 'theme': 'incident_response', 'document_title': 'NIST SP 800-61 Incident Handling'}
        ),
        RAGDocument(
            id='mitre-t1110',
            content=(
                'MITRE ATT&CK T1110 Brute Force: el atacante intenta adivinar credenciales o probar combinaciones '
                'de usuario y contraseña. Recomendado bloquear IP, activar MFA, limitar intentos y revisar logs de '
                'autenticación para detectar patrones de fuerza bruta.'
            ),
            metadata={'source': 'MITRE', 'technique': 'T1110', 'document_title': 'MITRE ATT&CK T1110'}
        ),
        RAGDocument(
            id='mitre-t1078',
            content=(
                'MITRE ATT&CK T1078 Valid Accounts: adversarios reutilizan credenciales válidas, a menudo desde '
                'horarios inusuales o IPs no habituales. Se recomienda revisar sesión, revocar tokens, cambiar '
                'contraseñas y validar si la actividad corresponde a un usuario real.'
            ),
            metadata={'source': 'MITRE', 'technique': 'T1078', 'document_title': 'MITRE ATT&CK T1078'}
        ),
        RAGDocument(
            id='soc-hardening',
            content=(
                'Hardening SOC: aplicar MFA obligatorio, controles de sesión, monitorización de IPs anómalas, '
                'alertas sobre accesos en horas extrañas y orden de contención con sign-off humano.'
            ),
            metadata={'source': 'SOC', 'theme': 'hardening', 'document_title': 'SOC Hardening Guidelines'}
        ),
    ]

    corpus_docs = load_corpus_documents(corpus_dir)
    return base_docs + corpus_docs


def ensure_default_index(persist_directory: str | None = None, force_rebuild: bool = False) -> LocalVectorStore:
    """Garantiza la existencia e integridad de la base vectorial con el corpus enriquecido."""
    store = LocalVectorStore(persist_directory=persist_directory)
    # Si la base está vacía, se solicita reconstrucción, o tiene menos de 8 documentos (índice legacy)
    if force_rebuild or len(store.documents) < 8:
        store.rebuild(build_default_knowledge())
    return store
