"""
h2o_client.py — H2O GPTe SDK wrapper for red teaming sessions.

Assumptions (h2ogpte==1.6.47):
  - H2OGPTE(address, api_key) is the main client class.
  - client.answer_question() returns an object with a `.content` str attribute
    for stateless, single-turn queries (no RAG collection required).
  - If answer_question is unavailable, falls back to a chat-session flow:
    create_chat_session_on_default_collection() + connect() context manager.
  - The LLM name can be configured via H2OGPTE_LLM env var; defaults to the
    server's default model when set to an empty string or omitted.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _get_client():
    """Build and return an authenticated H2OGPTE client."""
    from h2ogpte import H2OGPTE  # lazy import to surface missing-dep errors cleanly

    url = os.environ.get("H2OGPTE_URL", "").strip()
    api_key = os.environ.get("H2OGPTE_API_KEY", "").strip()

    if not url or not api_key:
        raise EnvironmentError(
            "H2OGPTE_URL and H2OGPTE_API_KEY environment variables must be set."
        )

    return H2OGPTE(address=url, api_key=api_key)


def send_prompt(
    prompt: str,
    system_prompt: Optional[str] = None,
    llm: Optional[str] = None,
) -> dict:
    """
    Send a single prompt to H2O GPTe and return a result dict.

    Args:
        prompt:        The adversarial payload text.
        system_prompt: Optional system-level instruction override.
        llm:           Model identifier; falls back to H2OGPTE_LLM env var.

    Returns:
        {
            "success": bool,
            "content": str | None,   # raw model response
            "model":   str | None,   # model identifier used
            "error":   str | None,   # populated only on failure
        }
    """
    llm_name = llm or os.environ.get("H2OGPTE_LLM", "")
    sys_prompt = system_prompt or "You are a helpful assistant."

    try:
        client = _get_client()

        # ── Primary path: stateless answer_question ──────────────────────────
        # answer_question avoids the need to manage collections/sessions,
        # which is ideal for independent red-team probe executions.
        try:
            kwargs = dict(
                question=prompt,
                system_prompt=sys_prompt,
                llm_args={"temperature": 0.2, "max_new_tokens": 1024},
            )
            if llm_name:
                kwargs["llm"] = llm_name

            reply = client.answer_question(**kwargs)
            content = reply.content if hasattr(reply, "content") else str(reply)
            return {"success": True, "content": content, "model": llm_name, "error": None}

        except AttributeError:
            # ── Fallback: chat-session flow ───────────────────────────────────
            logger.warning("answer_question unavailable; falling back to chat session.")
            chat_session_id = client.create_chat_session_on_default_collection()
            with client.connect(chat_session_id) as session:
                reply = session.query(prompt, timeout=120)
                content = reply.content if hasattr(reply, "content") else str(reply)
            return {"success": True, "content": content, "model": llm_name, "error": None}

    except EnvironmentError as exc:
        logger.error("Configuration error: %s", exc)
        return {"success": False, "content": None, "model": None, "error": str(exc)}
    except Exception as exc:
        logger.exception("H2OGPTE query failed")
        return {"success": False, "content": None, "model": llm_name, "error": str(exc)}
