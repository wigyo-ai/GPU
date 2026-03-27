"""
apply_hardened_config.py — Apply hardened_config.json to H2O GPTe via SDK.

Usage:
    python apply_hardened_config.py [--collection COLLECTION_ID] [--dry-run]

Requires env vars:
    H2OGPTE_URL       — base URL of H2O GPTe deployment
    H2OGPTE_API_KEY   — API key (admin key needed for admin_settings)

What it does:
    1. Loads hardened_config.json
    2. Applies guardrails_settings + llm_args to a target collection (or prints SDK code)
    3. Attempts admin rate-limit settings (skipped gracefully if not admin)
    4. Prints a ready-to-paste system_prompt
"""

import argparse
import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "hardened_config.json")


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return json.load(f)


def get_client():
    try:
        from h2ogpte import H2OGPTE
    except ImportError:
        print("ERROR: h2ogpte package not installed. Run: pip install h2ogpte")
        sys.exit(1)

    url = os.environ.get("H2OGPTE_URL", "").strip()
    api_key = os.environ.get("H2OGPTE_API_KEY", "").strip()
    if not url or not api_key:
        print("ERROR: H2OGPTE_URL and H2OGPTE_API_KEY must be set.")
        sys.exit(1)

    return H2OGPTE(address=url, api_key=api_key)


def apply_collection_settings(client, collection_id: str, config: dict, dry_run: bool):
    """Apply guardrails_settings to an existing collection."""
    gs = {k: v for k, v in config["guardrails_settings"].items() if not k.startswith("_")}

    if dry_run:
        print("\n[DRY RUN] Would call update_collection_settings with:")
        print(json.dumps({"guardrails_settings": gs}, indent=2))
        return

    try:
        from h2ogpte.models import CollectionSettings, GuardrailsSettings
        guardrails = GuardrailsSettings(**{
            k: v for k, v in gs.items()
            if k not in ("guardrails_llm",)   # exclude placeholder fields
        })
        settings = CollectionSettings(guardrails_settings=guardrails)
        client.update_collection_settings(collection_id, settings)
        print(f"  ✓ guardrails_settings applied to collection {collection_id}")
    except Exception as exc:
        print(f"  ✗ update_collection_settings failed: {exc}")
        print("    Tip: apply guardrails_settings manually via the H2O GPTe UI or SDK.")


def apply_admin_settings(client, config: dict, dry_run: bool):
    """Attempt to apply admin-level rate limits via set_global_configuration."""
    admin = config.get("admin_settings", {})
    limit = admin.get("max_queries_per_user_per_day")
    expiry = admin.get("api_key_expiry_hours")

    if dry_run:
        print(f"\n[DRY RUN] Would set max_queries_per_user_per_day = {limit}")
        print(f"[DRY RUN] Note: API key expiry ({expiry}h) must be set per-key via set_api_key_expiration()")
        return

    if limit:
        try:
            client.set_global_configuration(
                "max_queries_per_user_per_day",
                str(limit),
                can_overwrite=True,
                is_public=False,
            )
            print(f"  ✓ max_queries_per_user_per_day = {limit}")
        except Exception as exc:
            print(f"  ⚠ Admin rate limit skipped (admin key required): {exc}")

    if expiry:
        print(f"  ℹ  API key expiry ({expiry}h) must be set per-key via:")
        print(f"       client.set_api_key_expiration(api_key_id, <datetime>)")


def print_answer_question_snippet(config: dict):
    """Print a ready-to-use answer_question() call with all settings."""
    gs = {k: v for k, v in config["guardrails_settings"].items() if not k.startswith("_")}
    la = {k: v for k, v in config["llm_args"].items() if not k.startswith("_")}
    sp = config.get("system_prompt", "")

    print("\n" + "─" * 70)
    print("READY-TO-USE answer_question() SNIPPET")
    print("─" * 70)
    snippet = f"""
result = client.answer_question(
    question=user_prompt,
    system_prompt=\"\"\"{sp}\"\"\",
    llm_args={json.dumps(la, indent=4)},
    guardrails_settings={json.dumps(gs, indent=4)},
)
"""
    print(snippet)


def main():
    parser = argparse.ArgumentParser(description="Apply ATLAS hardened config to H2O GPTe")
    parser.add_argument("--collection", metavar="COLLECTION_ID",
                        help="Collection ID to apply guardrails_settings to")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be applied without making any changes")
    parser.add_argument("--snippet-only", action="store_true",
                        help="Only print the answer_question() snippet, no SDK calls")
    args = parser.parse_args()

    print(f"\nLoading config from: {CONFIG_FILE}")
    config = load_config()
    covered = config.get("techniques_covered", [])
    print(f"Coverage: {len(covered)} ATLAS techniques\n")

    if args.snippet_only:
        print_answer_question_snippet(config)
        return

    client = get_client()
    print(f"Connected to: {os.environ.get('H2OGPTE_URL')}")

    if args.collection:
        print(f"\n[1/2] Applying guardrails to collection: {args.collection}")
        apply_collection_settings(client, args.collection, config, args.dry_run)
    else:
        print("\n[1/2] No --collection specified; skipping collection guardrails update.")
        print("      To apply: python apply_hardened_config.py --collection <your-collection-id>")

    print("\n[2/2] Applying admin settings...")
    apply_admin_settings(client, config, args.dry_run)

    print_answer_question_snippet(config)
    print("─" * 70)
    print("Done. Copy the snippet above into your answer_question() calls.")
    print(f"System prompt is in: {CONFIG_FILE} → 'system_prompt' key")


if __name__ == "__main__":
    main()
