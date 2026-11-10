#!/usr/bin/env python3
"""Indexador local para la base de conocimiento del Copilot SOC-IA.

Este script construye la base vectorial local de conocimiento con documentos NIST/MITRE
y los playbooks del corpus Markdown. Reconstruye y sincroniza tanto la base del servicio
como la copia raíz del repositorio.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from rag_store import build_default_knowledge, LocalVectorStore


def build_index(output_dir: str = "./chroma_db") -> dict:
    docs = build_default_knowledge()

    # 1. Base local en output_dir
    target_path = Path(output_dir).resolve()
    store = LocalVectorStore(persist_directory=str(target_path))
    store.rebuild(docs)

    # 2. Base raíz del espacio de trabajo (chroma_db en la raíz del proyecto)
    root_chroma = Path(r"c:\Users\diego\Documents\Documentos\Inteligencia Artificial\chroma_db").resolve()
    if root_chroma != target_path:
        root_store = LocalVectorStore(persist_directory=str(root_chroma))
        root_store.rebuild(docs)

    sources = sorted(list({str(doc.metadata.get('source', 'unknown')) for doc in store.documents}))
    filenames = sorted(list({str(doc.metadata.get('filename')) for doc in store.documents if doc.metadata.get('filename')}))

    return {
        "indexed_documents": len(store.documents),
        "persist_directory": str(target_path),
        "root_chroma_directory": str(root_chroma),
        "sources": sources,
        "filenames": filenames,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Indexador RAG para SOC-IA')
    parser.add_argument('--output-dir', default='./chroma_db', help='Directorio local para la base vectorial')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = build_index(args.output_dir)
    print(f"[OK] Base vectorial creada exitosamente con {result['indexed_documents']} documentos.")
    print(f"Persistencia local: {result['persist_directory']}")
    print(f"Persistencia raíz : {result['root_chroma_directory']}")
    print(f"Fuentes indexadas : {', '.join(result['sources'])}")
    print(f"Archivos corpus   : {', '.join(result['filenames'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
