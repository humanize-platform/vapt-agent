"""
AI Security Tutor for VAPT Agent.

Now powered by Nebius Token Factory (OpenAI-compatible API) with Chroma vector search.

Key behaviours:
- Uses a Nebius-hosted model for chat.
- Uses a Nebius embedding model + Chroma to build a vector index over the
  VAPT Markdown report.
- The index is built ONCE per report (per process) and automatically rebuilt
  if the report content changes.
- Ensures that vectors from one report are never reused for another report
  by hashing the report content and recreating the index when it changes.
- Optionally enriches answers with web search via Tavily.

Environment variables:

# Nebius (required)
- NEBIUS_API_KEY            : Nebius Token Factory API key
- NEBIUS_BASE_URL           : (optional) e.g. "https://api.tokenfactory.nebius.com/v1"
- NEBIUS_TUTOR_MODEL        : (optional) chat model id for tutor
- NEBIUS_EMBEDDING_MODEL    : embedding model id for vector search (REQUIRED to enable Chroma search)

# Optional web search
- TAVILY_API_KEY            : enables web search if set
"""

import os
import hashlib
from typing import List, Tuple, Dict
from dataclasses import dataclass

import requests
from openai import OpenAI

from prompt import get_tutor_system_prompt

# Try to import Chroma, but degrade gracefully if not installed
try:
    import chromadb

    CHROMA_AVAILABLE = True
except ImportError:
    chromadb = None
    CHROMA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Simple helpers
# ---------------------------------------------------------------------------


def _normalize(text: str) -> str:
    return text.lower()


def _extract_report_sections(
    report_md: str, max_section_chars: int = 2000
) -> List[str]:
    """
    Split the markdown report into logical sections based on '## ' headings.

    If sections are very large, they are further split into smaller chunks.
    """
    if not report_md:
        return []

    sections: List[str] = []
    current: List[str] = []

    lines = report_md.splitlines()
    for line in lines:
        if line.startswith("## "):
            if current:
                sections.append("\n".join(current).strip())
                current = []
        current.append(line)

    if current:
        sections.append("\n".join(current).strip())

    if not sections:
        sections = [report_md]

    # Further split oversized sections into smaller chunks
    final_chunks: List[str] = []
    for sec in sections:
        if len(sec) <= max_section_chars:
            final_chunks.append(sec)
        else:
            # naive split by paragraphs
            paras = sec.split("\n\n")
            chunk: List[str] = []
            size = 0
            for p in paras:
                p_len = len(p) + 2
                if size + p_len > max_section_chars and chunk:
                    final_chunks.append("\n\n".join(chunk))
                    chunk = [p]
                    size = p_len
                else:
                    chunk.append(p)
                    size += p_len
            if chunk:
                final_chunks.append("\n\n".join(chunk))

    return final_chunks


def _web_search_tavily(query: str, max_results: int = 3) -> str:
    """
    Optional: perform web search via Tavily Search API.

    Requires TAVILY_API_KEY in env. If not present or call fails,
    returns an empty string and the tutor will just rely on the report.
    """
    api_key = os.getenv("TAVILY_API_KEY")
    if not api_key:
        return ""

    try:
        payload = {
            "api_key": api_key,
            "query": query,
            "max_results": max_results,
            "include_answer": True,
            "search_depth": "basic",
        }
        resp = requests.post(
            "https://api.tavily.com/search",
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        parts: List[str] = []
        answer = data.get("answer")
        if answer:
            parts.append(f"Direct answer: {answer}")

        results = data.get("results") or []
        for r in results[:max_results]:
            title = r.get("title") or "Untitled"
            url = r.get("url") or ""
            content = r.get("content") or ""
            parts.append(f"- {title}\n  {content[:300]}...\n  Source: {url}")

        return "\n".join(parts) if parts else ""
    except Exception:
        # Fail silently – we don't want the tutor to break if search fails
        return ""


# ---------------------------------------------------------------------------
# Security Tutor with Nebius + Chroma
# ---------------------------------------------------------------------------


@dataclass
class TutorConfig:
    base_url: str
    api_key: str
    model: str
    embedding_model: str | None


class SecurityTutor:
    """AI-powered security education assistant backed by Nebius + Chroma."""

    def __init__(self):
        """
        Initialize the Security Tutor with Nebius OpenAI-compatible client.

        Required:
          - NEBIUS_API_KEY

        Optional:
          - NEBIUS_BASE_URL (defaults to Nebius Token Factory base URL)
          - NEBIUS_TUTOR_MODEL
          - NEBIUS_EMBEDDING_MODEL (required to enable Chroma vector search)
        """
        api_key = os.getenv("NEBIUS_API_KEY")

        if not api_key:
            self.client = None
            self.available = False
            self.config = None
            self.chroma_client = None
            self.vector_enabled = False
            self._raw_report = ""
            self._report_hash = None
            self._collection = None
            return

        base_url = os.getenv(
            "NEBIUS_BASE_URL",
            "https://api.tokenfactory.nebius.com/v1",  # Nebius OpenAI-compatible base URL
        )
        model = os.getenv(
            "NEBIUS_TUTOR_MODEL",
            "meta-llama/Meta-Llama-3.1-70B-Instruct",  # example; override with your chosen model
        )
        embedding_model = os.getenv(
            "NEBIUS_EMBEDDING_MODEL",  # REQUIRED for vector search
            None,
        )

        self.config = TutorConfig(
            base_url=base_url,
            api_key=api_key,
            model=model,
            embedding_model=embedding_model,
        )
        self.client = OpenAI(base_url=self.config.base_url, api_key=self.config.api_key)
        self.available = True

        # Chroma setup
        if CHROMA_AVAILABLE and self.config.embedding_model:
            # Ephemeral in-memory store is fine for a single process
            self.chroma_client = chromadb.EphemeralClient()
            self.vector_enabled = True
        else:
            self.chroma_client = None
            self.vector_enabled = False

        # Per-report state
        self._raw_report: str = ""
        self._report_hash: str | None = None
        self._collection = None  # Chroma collection holding current report vectors

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    def chat(
        self,
        message: str,
        report_context: str,
        history: List[Tuple[str, str]],
    ) -> str:
        """
        Handle a chat message from the user.

        Args:
            message: User's question
            report_context: Full VAPT report markdown for THIS user/run
            history: Previous chat messages [(user_msg, assistant_msg), ...]

        Behaviour:
            - If the report content has changed since last call, rebuild the
              vector index just once and store it.
            - Then run vector search on the stored index for this question.
            - Never reuse vectors from a previous report for the new report.
        """
        if not self.available or not self.client:
            return (
                "🔧 AI Tutor is not configured yet.\n\n"
                "Please set NEBIUS_API_KEY (and optionally NEBIUS_TUTOR_MODEL) "
                "in your environment to enable the tutor."
            )

        # 1) Ensure the index is up-to-date for THIS report
        self._ensure_report_index(report_context)

        # 2) Retrieve relevant snippets from the currently indexed report
        report_snippets = self._search_report_with_vectors(message)

        # 3) Optional web search (if Tavily API key is configured)
        web_snippets = _web_search_tavily(message)
        web_note = (
            "\n\n---\n\nWeb search snippets:\n" + web_snippets
            if web_snippets
            else "\n\n(Web search not configured or returned no results.)"
        )

        # 4) Build system prompt with clear grounding instructions
        system_prompt = self._build_system_prompt(
            report_snippets=report_snippets,
            include_web=bool(web_snippets),
        )

        # 5) Build messages (system + history + current question)
        messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]

        for user_msg, assistant_msg in history:
            if user_msg:
                messages.append({"role": "user", "content": user_msg})
            if assistant_msg:
                messages.append({"role": "assistant", "content": assistant_msg})

        user_content = (
            f"{message}\n\n"
            "-----\n\n"
            "Use the following VAPT report excerpts as your primary source of truth:\n\n"
            f"{report_snippets}\n"
            f"{web_note}"
        )
        messages.append({"role": "user", "content": user_content})

        try:
            completion = self.client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=0.4,
                max_tokens=800,
            )
            return completion.choices[0].message.content
        except Exception as e:
            return f"❌ Error communicating with Security Tutor (Nebius): {str(e)}"

    # ------------------------------------------------------------------ #
    # Report index management (build once per report)
    # ------------------------------------------------------------------ #

    def _ensure_report_index(self, report_md: str) -> None:
        """
        Ensure that the vector index reflects the given report.

        - If no report or same report as before -> do nothing.
        - If a different report -> rebuild vectors so we NEVER reuse old vectors
          for a new report.
        """
        report_md = report_md or ""

        # If we never had a report and still don't, nothing to do
        if not report_md and not self._raw_report:
            return

        new_hash = hashlib.sha256(report_md.encode("utf-8")).hexdigest()

        # If hash matches, it's the same report -> keep existing vectors
        if self._report_hash == new_hash:
            return

        # Report changed: update internal state and rebuild index
        self._raw_report = report_md
        self._report_hash = new_hash

        if (
            not self.vector_enabled
            or not self.chroma_client
            or not self.config.embedding_model
        ):
            # We still store the report, so fallback search can use it
            self._collection = None
            return

        # Build a fresh collection just for this report
        sections = _extract_report_sections(self._raw_report)
        if not sections:
            self._collection = None
            return

        # Collection name derived from hash to avoid mixing
        coll_name = f"vapt_report_{self._report_hash[:8]}"

        # Create or get collection; then clear any previous contents
        self._collection = self.chroma_client.get_or_create_collection(name=coll_name)
        try:
            self._collection.delete(where={})
        except Exception:
            # Older Chroma versions might not like empty filters; safely ignore
            pass

        # Embed and add sections
        ids = [f"chunk-{i}" for i in range(len(sections))]
        embeddings = self._embed_texts(sections)

        self._collection.add(ids=ids, documents=sections, embeddings=embeddings)

    # ------------------------------------------------------------------ #
    # Vector search over report using Chroma + Nebius embeddings
    # ------------------------------------------------------------------ #

    def _embed_texts(self, texts: List[str]) -> List[List[float]]:
        """
        Create embeddings for a list of texts using Nebius embedding model.
        """
        if not self.config.embedding_model:
            raise RuntimeError(
                "NEBIUS_EMBEDDING_MODEL is not set; cannot perform vector search."
            )

        resp = self.client.embeddings.create(
            model=self.config.embedding_model,
            input=texts,
        )
        return [item.embedding for item in resp.data]

    def _search_report_with_vectors(self, question: str, top_k: int = 4) -> str:
        """
        Use the current Chroma collection (for the current report) to retrieve
        the most relevant chunks. Falls back to simple truncation of the report
        if vector search is not available.
        """
        if not self._raw_report:
            return "No VAPT report is currently available."

        # If vector search is not enabled or we have no collection, fallback
        if not self.vector_enabled or not self._collection:
            # Cheap fallback: Executive Summary + Key Findings, or first 2000 chars
            sections = _extract_report_sections(self._raw_report)
            fallback = [
                s
                for s in sections
                if "executive summary" in _normalize(s)
                or "key findings" in _normalize(s)
            ]
            if fallback:
                return "\n\n---\n\n".join(fallback)[:2000]
            return self._raw_report[:2000]

        try:
            # Embed the question and query the collection
            q_embedding = self._embed_texts([question])[0]

            results = self._collection.query(
                query_embeddings=[q_embedding],
                n_results=top_k,
            )

            docs = results.get("documents", [[]])[0] if results else []
            if not docs:
                return self._raw_report[:2000]

            joined = "\n\n---\n\n".join(docs)
            return joined[:2000]
        except Exception:
            # Any failure -> fall back to raw report
            return self._raw_report[:2000]

    # ------------------------------------------------------------------ #
    # System prompt builder
    # ------------------------------------------------------------------ #

    def _build_system_prompt(self, report_snippets: str, include_web: bool) -> str:
        """
        Build the system prompt for the AI tutor.

        Args:
            report_snippets: Text retrieved from the VAPT report
            include_web: Whether web search snippets are available

        Returns:
            System prompt string
        """
        return get_tutor_system_prompt(report_snippets, include_web)


# Global tutor instance (shared within the process)
_tutor_instance: SecurityTutor | None = None


def get_tutor() -> SecurityTutor:
    """
    Get or create the global SecurityTutor instance.

    Note: Vectors are tied to the report markdown passed into `chat()`.
    Whenever a new report is used, the tutor automatically rebuilds its
    index so that vectors from a previous report are never reused.
    """
    global _tutor_instance
    if _tutor_instance is None:
        _tutor_instance = SecurityTutor()
    return _tutor_instance
