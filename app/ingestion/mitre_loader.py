"""
Downloads MITRE ATT&CK Enterprise STIX bundle and loads it into Neo4j.
Parses tactics, techniques, sub-techniques, groups, software, and mitigations.
"""

import json
import logging
from pathlib import Path

import requests
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_PATH = Path("./data/mitre/enterprise-attack.json")


class MitreLoader:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    def load(self, force_refresh: bool = False) -> dict[str, int]:
        bundle = self._download_data()
        objects = self._parse_objects(bundle)

        with self.driver.session() as session:
            if force_refresh:
                session.run("MATCH (n) DETACH DELETE n")
                logger.info("Cleared Neo4j database")
            self._create_constraints(session)
            nodes_created = self._load_nodes(session, objects)
            edges_created = self._load_relationships(session, objects, bundle["objects"])

        logger.info("Loaded %d nodes and %d edges", nodes_created, edges_created)
        return {"nodes_created": nodes_created, "edges_created": edges_created}

    def _download_data(self) -> dict:
        if CACHE_PATH.exists():
            logger.info("Loading MITRE data from cache: %s", CACHE_PATH)
            with open(CACHE_PATH, encoding="utf-8") as f:
                return json.load(f)

        logger.info("Downloading MITRE ATT&CK data from GitHub...")
        resp = requests.get(MITRE_URL, timeout=120)
        resp.raise_for_status()
        data = resp.json()

        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info("Cached MITRE data to %s", CACHE_PATH)
        return data

    def _parse_objects(self, bundle: dict) -> dict[str, list]:
        objects: dict[str, list] = {
            "tactics": [],
            "techniques": [],
            "subtechniques": [],
            "groups": [],
            "software": [],
            "mitigations": [],
        }

        for obj in bundle.get("objects", []):
            obj_type = obj.get("type", "")
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            if obj_type == "x-mitre-tactic":
                objects["tactics"].append(self._parse_tactic(obj))
            elif obj_type == "attack-pattern":
                if obj.get("x_mitre_is_subtechnique"):
                    objects["subtechniques"].append(self._parse_technique(obj))
                else:
                    objects["techniques"].append(self._parse_technique(obj))
            elif obj_type == "intrusion-set":
                objects["groups"].append(self._parse_group(obj))
            elif obj_type in ("tool", "malware"):
                objects["software"].append(self._parse_software(obj, obj_type))
            elif obj_type == "course-of-action":
                objects["mitigations"].append(self._parse_mitigation(obj))

        return objects

    def _parse_tactic(self, obj: dict) -> dict:
        ext_refs = obj.get("external_references", [])
        external_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )
        return {
            "id": obj["id"],
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "external_id": external_id,
            "shortname": obj.get("x_mitre_shortname", ""),
        }

    def _parse_technique(self, obj: dict) -> dict:
        ext_refs = obj.get("external_references", [])
        external_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )
        tactic_refs = [
            kcp["phase_name"]
            for kcp in obj.get("kill_chain_phases", [])
            if kcp.get("kill_chain_name") == "mitre-attack"
        ]
        return {
            "id": obj["id"],
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "external_id": external_id,
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "platforms": ", ".join(obj.get("x_mitre_platforms", [])),
            "detection": obj.get("x_mitre_detection", ""),
            "tactic_refs": tactic_refs,
        }

    def _parse_group(self, obj: dict) -> dict:
        ext_refs = obj.get("external_references", [])
        external_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )
        return {
            "id": obj["id"],
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "external_id": external_id,
            "aliases": ", ".join(obj.get("aliases", [])),
        }

    def _parse_software(self, obj: dict, software_type: str) -> dict:
        ext_refs = obj.get("external_references", [])
        external_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )
        return {
            "id": obj["id"],
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "external_id": external_id,
            "software_type": software_type,
        }

    def _parse_mitigation(self, obj: dict) -> dict:
        ext_refs = obj.get("external_references", [])
        external_id = next(
            (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )
        return {
            "id": obj["id"],
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "external_id": external_id,
        }

    def _create_constraints(self, session):
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Tactic) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:SubTechnique) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Group) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Software) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.id IS UNIQUE",
        ]
        for c in constraints:
            session.run(c)

    def _load_nodes(self, session, objects: dict) -> int:
        count = 0

        for tactic in objects["tactics"]:
            session.run(
                "MERGE (n:Tactic {id: $id}) SET n += $props",
                id=tactic["id"],
                props=tactic,
            )
            count += 1

        for tech in objects["techniques"]:
            session.run(
                "MERGE (n:Technique {id: $id}) SET n += $props",
                id=tech["id"],
                props={k: v for k, v in tech.items() if k != "tactic_refs"},
            )
            count += 1

        for sub in objects["subtechniques"]:
            session.run(
                "MERGE (n:SubTechnique {id: $id}) SET n += $props",
                id=sub["id"],
                props={k: v for k, v in sub.items() if k != "tactic_refs"},
            )
            count += 1

        for group in objects["groups"]:
            session.run(
                "MERGE (n:Group {id: $id}) SET n += $props",
                id=group["id"],
                props=group,
            )
            count += 1

        for sw in objects["software"]:
            session.run(
                "MERGE (n:Software {id: $id}) SET n += $props",
                id=sw["id"],
                props=sw,
            )
            count += 1

        for mit in objects["mitigations"]:
            session.run(
                "MERGE (n:Mitigation {id: $id}) SET n += $props",
                id=mit["id"],
                props=mit,
            )
            count += 1

        # Link techniques and subtechniques to tactics via shortname
        tactic_map = {t["shortname"]: t["id"] for t in objects["tactics"]}
        for tech in objects["techniques"] + objects["subtechniques"]:
            for tactic_shortname in tech.get("tactic_refs", []):
                tactic_id = tactic_map.get(tactic_shortname)
                if tactic_id:
                    label = "SubTechnique" if tech["is_subtechnique"] else "Technique"
                    session.run(
                        f"MATCH (t:{label} {{id: $tech_id}}), (ta:Tactic {{id: $tactic_id}}) "
                        "MERGE (t)-[:BELONGS_TO]->(ta)",
                        tech_id=tech["id"],
                        tactic_id=tactic_id,
                    )

        return count

    def _load_relationships(self, session, objects: dict, stix_objects: list) -> int:
        # Build id→label map
        id_label: dict[str, str] = {}
        for t in objects["tactics"]:
            id_label[t["id"]] = "Tactic"
        for t in objects["techniques"]:
            id_label[t["id"]] = "Technique"
        for t in objects["subtechniques"]:
            id_label[t["id"]] = "SubTechnique"
        for g in objects["groups"]:
            id_label[g["id"]] = "Group"
        for s in objects["software"]:
            id_label[s["id"]] = "Software"
        for m in objects["mitigations"]:
            id_label[m["id"]] = "Mitigation"

        count = 0
        for obj in stix_objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            rel_type = obj.get("relationship_type", "")

            src_label = id_label.get(src)
            tgt_label = id_label.get(tgt)
            if not src_label or not tgt_label:
                continue

            if rel_type == "uses":
                neo4j_rel = "USES"
            elif rel_type == "mitigates":
                neo4j_rel = "MITIGATED_BY"
                src, tgt = tgt, src
                src_label, tgt_label = tgt_label, src_label
            elif rel_type == "subtechnique-of":
                neo4j_rel = "SUBTECHNIQUE_OF"
            else:
                continue

            session.run(
                f"MATCH (a:{src_label} {{id: $src}}), (b:{tgt_label} {{id: $tgt}}) MERGE (a)-[:{neo4j_rel}]->(b)",
                src=src,
                tgt=tgt,
            )
            count += 1

        return count

    def close(self):
        self.driver.close()
