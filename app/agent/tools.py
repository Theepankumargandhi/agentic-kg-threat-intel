"""
LangChain tools wrapping the retrieval layer.
Module-level graph_store and vector_store are set by graph.py.
"""

from typing import Any

from langchain_core.tools import tool

# Set by graph.py at build time
graph_store: Any = None
vector_store: Any = None


@tool
def search_techniques(query: str) -> str:
    """
    Search the MITRE ATT&CK technique database using semantic similarity.
    Use this to find techniques related to a concept, behavior, or attack method.
    Input: a natural language description of the technique or behavior.
    """
    if vector_store is None:
        return "VectorStore not initialized."
    results = vector_store.query(query, top_k=5)
    if not results:
        return "No techniques found."
    lines = []
    for r in results:
        lines.append(f"- {r.get('name', 'Unknown')} ({r.get('external_id', 'N/A')}): {r.get('description', '')[:200]}")
    return "\n".join(lines)


@tool
def query_threat_groups(group_name: str) -> str:
    """
    Query the knowledge graph for a specific threat actor group.
    Returns the techniques and attack paths associated with the group.
    Input: the name of a threat actor group (e.g., 'APT29', 'Lazarus Group').
    """
    if graph_store is None:
        return "GraphStore not initialized."
    path = graph_store.get_attack_path(group_name, limit=15)
    nodes = path.get("nodes", [])
    if not nodes:
        return f"No data found for group: {group_name}"
    techniques = [n for n in nodes if n.get("type") in ("Technique", "SubTechnique")]
    lines = [f"Threat Actor: {group_name}", f"Known techniques ({len(techniques)}):"]
    for t in techniques[:10]:
        lines.append(f"  - {t.get('name', 'Unknown')} ({t.get('properties', {}).get('external_id', 'N/A')})")
    return "\n".join(lines)


@tool
def get_attack_path(group_name: str) -> str:
    """
    Get the full attack chain (tactics → techniques) used by a threat group.
    Returns a structured summary of the group's tactics and techniques.
    Input: threat group name (e.g., 'FIN7', 'APT41').
    """
    if graph_store is None:
        return "GraphStore not initialized."
    path = graph_store.get_attack_path(group_name)
    nodes = path.get("nodes", [])
    edges = path.get("edges", [])
    if not nodes:
        return f"No attack path found for: {group_name}"

    by_type: dict[str, list] = {}
    for node in nodes:
        ntype = node.get("type", "Unknown")
        by_type.setdefault(ntype, []).append(node.get("name", "Unknown"))

    lines = [f"Attack Path for {group_name}:"]
    for ntype, names in by_type.items():
        lines.append(f"  {ntype}s: {', '.join(names[:8])}")
    lines.append(f"Total: {len(nodes)} nodes, {len(edges)} relationships")
    return "\n".join(lines)


@tool
def get_mitigations(technique_id: str) -> str:
    """
    Get recommended mitigations for a specific MITRE ATT&CK technique.
    Input: a MITRE technique ID (e.g., 'T1566', 'T1078', 'T1059.001').
    """
    if graph_store is None:
        return "GraphStore not initialized."
    mitigations = graph_store.get_technique_mitigations(technique_id)
    if not mitigations:
        return f"No mitigations found for technique: {technique_id}"
    lines = [f"Mitigations for {technique_id}:"]
    for m in mitigations:
        lines.append(
            f"  - {m.get('name', 'Unknown')} ({m.get('external_id', 'N/A')}): {m.get('description', '')[:150]}"
        )
    return "\n".join(lines)
