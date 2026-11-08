#!/usr/bin/env python3
"""Indexador local para la base de conocimiento del Copilot SOC-IA.

Este script construye la base vectorial local de conocimiento con documentos NIST/MITRE.
Se usa como base para la capa RAG del proyecto y funciona sin necesidad de un servicio externo.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from rag_store import build_default_knowledge, ensure_default_index


def build_index(output_dir: str = "./chroma_db") -> dict:
    store = ensure_default_index(output_dir)
    return {
        "indexed_documents": len(store.documents),
        "persist_directory": str(Path(output_dir).resolve()),
        "sources": [doc.metadata.get('source', 'unknown') for doc in store.documents],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Indexador RAG para SOC-IA')
    parser.add_argument('--output-dir', default='./chroma_db', help='Directorio local para la base vectorial')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = build_index(args.output_dir)
    print(f"[OK] Base vectorial creada: {result['indexed_documents']} documentos indexados")
    print(f"Persistencia: {result['persist_directory']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
