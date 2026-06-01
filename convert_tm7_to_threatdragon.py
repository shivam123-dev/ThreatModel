"""
Convert a Microsoft Threat Modeling Tool (.tm7) file to
OWASP Threat Dragon v2.x JSON format for import at:
https://www.threatdragon.com/#/local/threatmodel/import
"""
import xml.etree.ElementTree as ET
import json
import uuid
import sys
import os

# Namespaces used in the .tm7 XML
NS = {
    "tm": "http://schemas.datacontract.org/2004/07/ThreatModeling.Model",
    "abs": "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts",
    "kb": "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase",
    "arr": "http://schemas.microsoft.com/2003/10/Serialization/Arrays",
    "ser": "http://schemas.microsoft.com/2003/10/Serialization/",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}

STRIDE_MAP = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}


def find_property(properties_el, display_name):
    """Extract a property value from the Properties element by DisplayName."""
    if properties_el is None:
        return ""
    # Properties contains {arr}anyType children, each with {kb}DisplayName, {kb}Value, etc.
    for prop in properties_el:
        dn = prop.find("{%s}DisplayName" % NS["kb"])
        if dn is not None and dn.text == display_name:
            val = prop.find("{%s}Value" % NS["kb"])
            if val is not None and val.text:
                return val.text
            # For list attributes, check SelectedIndex and Value/{arr}string children
            si = prop.find("{%s}SelectedIndex" % NS["kb"])
            if si is not None and si.text is not None:
                idx = int(si.text)
                values = val.findall("{%s}string" % NS["arr"]) if val is not None else []
                if 0 <= idx < len(values) and values[idx].text:
                    return values[idx].text
            return ""
    return ""


def find_bool_property(properties_el, display_name):
    val = find_property(properties_el, display_name).lower()
    return val in ("true", "yes", "1")


def parse_elements(drawing_surface):
    """Parse Borders (stencils) and Lines (connectors) from a DrawingSurfaceModel."""
    elements = {}
    flows = {}
    boundaries = {}

    # Parse Borders (External Entities, Processes, Data Stores, Trust Boundaries)
    borders = drawing_surface.find("{%s}Borders" % NS["tm"])
    if borders is None:
        borders = drawing_surface.find("Borders")

    if borders is not None:
        for kv in borders.findall("{%s}KeyValueOfguidanyType" % NS["arr"]):
            key_el = kv.find("{%s}Key" % NS["arr"])
            val_el = kv.find("{%s}Value" % NS["arr"])
            if key_el is None or val_el is None:
                continue

            guid = key_el.text
            generic_type = None
            gt_el = val_el.find("{%s}GenericTypeId" % NS["abs"])
            if gt_el is not None:
                generic_type = gt_el.text

            props = val_el.find("{%s}Properties" % NS["abs"])
            name = find_property(props, "Name")
            oos = find_bool_property(props, "Out Of Scope")
            oos_reason = find_property(props, "Reason For Out Of Scope")

            left = val_el.find("{%s}Left" % NS["abs"])
            top = val_el.find("{%s}Top" % NS["abs"])
            width = val_el.find("{%s}Width" % NS["abs"])
            height = val_el.find("{%s}Height" % NS["abs"])

            x = int(left.text) if left is not None and left.text else 0
            y = int(top.text) if top is not None and top.text else 0
            w = int(width.text) if width is not None and width.text else 100
            h = int(height.text) if height is not None and height.text else 80

            if generic_type == "GE.EI":
                elements[guid] = {
                    "type": "tm.Actor",
                    "shape": "actor",
                    "name": name,
                    "x": x, "y": y, "w": w, "h": h,
                    "outOfScope": oos,
                    "reasonOutOfScope": oos_reason,
                    "providesAuthentication": False,
                    "threats": [],
                }
            elif generic_type == "GE.P":
                elements[guid] = {
                    "type": "tm.Process",
                    "shape": "process",
                    "name": name,
                    "x": x, "y": y, "w": w, "h": h,
                    "outOfScope": oos,
                    "reasonOutOfScope": oos_reason,
                    "privilegeLevel": "",
                    "threats": [],
                }
            elif generic_type == "GE.DS":
                elements[guid] = {
                    "type": "tm.Store",
                    "shape": "store",
                    "name": name,
                    "x": x, "y": y, "w": w, "h": h,
                    "outOfScope": oos,
                    "reasonOutOfScope": oos_reason,
                    "isALog": find_bool_property(props, "Stores Log Data"),
                    "storesCredentials": find_bool_property(props, "Stores Credentials"),
                    "isEncrypted": find_bool_property(props, "Encrypted"),
                    "isSigned": find_bool_property(props, "Signed"),
                    "threats": [],
                }
            elif generic_type in ("GE.TB.B", "GE.TB.L"):
                boundaries[guid] = {
                    "name": name,
                    "x": x, "y": y, "w": w, "h": h,
                }

    # Parse Lines (Data Flows / Connectors)
    lines = drawing_surface.find("{%s}Lines" % NS["tm"])
    if lines is None:
        lines = drawing_surface.find("Lines")

    if lines is not None:
        for kv in lines.findall("{%s}KeyValueOfguidanyType" % NS["arr"]):
            key_el = kv.find("{%s}Key" % NS["arr"])
            val_el = kv.find("{%s}Value" % NS["arr"])
            if key_el is None or val_el is None:
                continue

            guid = key_el.text
            props = val_el.find("{%s}Properties" % NS["abs"])
            name = find_property(props, "Name")
            oos = find_bool_property(props, "Out Of Scope")
            oos_reason = find_property(props, "Reason For Out Of Scope")

            src_guid_el = val_el.find("{%s}SourceGuid" % NS["abs"])
            tgt_guid_el = val_el.find("{%s}TargetGuid" % NS["abs"])
            src_guid = src_guid_el.text if src_guid_el is not None else ""
            tgt_guid = tgt_guid_el.text if tgt_guid_el is not None else ""

            hx_el = val_el.find("{%s}HandleX" % NS["abs"])
            hy_el = val_el.find("{%s}HandleY" % NS["abs"])
            sx_el = val_el.find("{%s}SourceX" % NS["abs"])
            sy_el = val_el.find("{%s}SourceY" % NS["abs"])
            tx_el = val_el.find("{%s}TargetX" % NS["abs"])
            ty_el = val_el.find("{%s}TargetY" % NS["abs"])

            flows[guid] = {
                "name": name,
                "sourceGuid": src_guid,
                "targetGuid": tgt_guid,
                "outOfScope": oos,
                "reasonOutOfScope": oos_reason,
                "isEncrypted": find_bool_property(props, "Provides Confidentiality"),
                "protocol": "",
                "threats": [],
                "vertices": [],
            }
            # Add midpoint vertex if available
            if hx_el is not None and hy_el is not None:
                try:
                    flows[guid]["vertices"].append({
                        "x": int(hx_el.text),
                        "y": int(hy_el.text),
                    })
                except (ValueError, TypeError):
                    pass

    return elements, flows, boundaries


def parse_threats(threat_model_root):
    """Parse ThreatInstances from the ThreatModel."""
    threats = []

    # Find ThreatInstances
    ti = threat_model_root.find("{%s}ThreatInstances" % NS["tm"])
    if ti is None:
        ti = threat_model_root.find("ThreatInstances")
    if ti is None:
        return threats

    for kv in ti.findall("{%s}KeyValueOfstringThreatpc_P0_PhOB" % NS["arr"]):
        val = kv.find("{%s}Value" % NS["arr"])
        if val is None:
            continue

        threat_id_el = val.find("{%s}Id" % NS["kb"])
        state_el = val.find("{%s}State" % NS["kb"])
        priority_el = val.find("{%s}Priority" % NS["kb"])
        src_el = val.find("{%s}SourceGuid" % NS["kb"])
        tgt_el = val.find("{%s}TargetGuid" % NS["kb"])
        flow_el = val.find("{%s}FlowGuid" % NS["kb"])
        state_info_el = val.find("{%s}StateInformation" % NS["kb"])

        # Extract properties dict
        props_el = val.find("{%s}Properties" % NS["kb"])
        props = {}
        if props_el is not None:
            for pkv in props_el.findall("{%s}KeyValueOfstringstring" % NS["arr"]):
                pk = pkv.find("{%s}Key" % NS["arr"])
                pv = pkv.find("{%s}Value" % NS["arr"])
                if pk is not None and pk.text and pv is not None:
                    props[pk.text] = pv.text or ""

        title = props.get("Title", "")
        description = props.get("UserThreatDescription", "")
        category = props.get("UserThreatCategory", "")
        priority = priority_el.text if priority_el is not None and priority_el.text else "Medium"
        state = state_el.text if state_el is not None and state_el.text else "Open"
        state_info = state_info_el.text if state_info_el is not None and state_info_el.text else ""
        flow_guid = flow_el.text if flow_el is not None else ""
        src_guid = src_el.text if src_el is not None else ""
        tgt_guid = tgt_el.text if tgt_el is not None else ""

        # Map state
        td_status = "Open"
        if state == "Mitigated":
            td_status = "Mitigated"
        elif state == "Not Applicable":
            td_status = "N/A"

        # Map category to STRIDE type
        stride_type = category
        if category in STRIDE_MAP:
            stride_type = STRIDE_MAP[category]
        elif not stride_type:
            # Try to infer from title
            for k, v in STRIDE_MAP.items():
                if v.lower() in title.lower():
                    stride_type = v
                    break

        threats.append({
            "id": str(uuid.uuid4()),
            "title": title,
            "status": td_status,
            "severity": priority,
            "type": stride_type,
            "description": description,
            "mitigation": state_info,
            "modelType": "STRIDE",
            "flowGuid": flow_guid,
            "sourceGuid": src_guid,
            "targetGuid": tgt_guid,
        })

    return threats


def assign_threats(threats, elements, flows):
    """Assign each threat to the appropriate element or flow."""
    for threat in threats:
        flow_guid = threat.pop("flowGuid", "")
        src_guid = threat.pop("sourceGuid", "")
        tgt_guid = threat.pop("targetGuid", "")

        # Prefer assigning to the flow
        if flow_guid and flow_guid in flows:
            flows[flow_guid]["threats"].append(threat)
        # Then try target element
        elif tgt_guid and tgt_guid in elements:
            elements[tgt_guid]["threats"].append(threat)
        # Then try source element
        elif src_guid and src_guid in elements:
            elements[src_guid]["threats"].append(threat)


def build_level0_diagram(elements_lookup=None):
    """Build a DFD Level 0 (Context) diagram for Threat Dragon."""
    cells = []
    z = 1

    # ── Trust Boundary ──
    cells.append({
        "shape": "trust-boundary-box",
        "id": str(uuid.uuid4()),
        "zIndex": -1,
        "type": "tm.BoundaryBox",
        "position": {"x": 380, "y": 180},
        "size": {"width": 540, "height": 500},
        "attrs": {},
        "data": {
            "name": "Flipkart Internal Network",
            "description": "",
            "isTrustBoundary": True,
        },
    })

    # ── External Entities (Actors) ──
    actors = {
        "l0-customer":  {"name": "E1 Customer (Mobile/Web)",         "x": 40,   "y": 100,  "w": 160, "h": 80},
        "l0-seller":    {"name": "E2 Seller",                        "x": 40,   "y": 320,  "w": 160, "h": 80},
        "l0-admin":     {"name": "E3 Flipkart Admin",                "x": 40,   "y": 540,  "w": 160, "h": 80},
        "l0-payment":   {"name": "E4 Payment Gateway (Razorpay/PayU)", "x": 1060, "y": 100, "w": 180, "h": 80},
        "l0-logistics": {"name": "E5 Logistics (Ekart)",             "x": 1060,  "y": 320, "w": 180, "h": 80},
        "l0-sms":       {"name": "E6 SMS/Email Provider",            "x": 1060,  "y": 540, "w": 180, "h": 80},
    }
    for aid, a in actors.items():
        cells.append({
            "position": {"x": a["x"], "y": a["y"]},
            "size": {"width": a["w"], "height": a["h"]},
            "shape": "actor",
            "id": aid,
            "zIndex": z,
            "type": "tm.Actor",
            "data": {
                "name": a["name"],
                "description": "",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": False,
                "threats": [],
                "providesAuthentication": False,
            },
        })
        z += 1

    # ── Central Process ──
    sys_id = "l0-flipkart-platform"
    cells.append({
        "position": {"x": 450, "y": 250},
        "size": {"width": 400, "height": 180},
        "shape": "process",
        "id": sys_id,
        "zIndex": z,
        "type": "tm.Process",
        "data": {
            "name": "Flipkart Platform (Microservices)",
            "description": "Central e-commerce platform comprising API Gateway, Auth, Product, Cart, Order, Payment, Seller, and Notification microservices.",
            "outOfScope": False,
            "reasonOutOfScope": "",
            "hasOpenThreats": False,
            "threats": [],
            "privilegeLevel": "",
        },
    })
    z += 1

    # ── Backend Database ──
    db_id = "l0-backend-db"
    cells.append({
        "position": {"x": 500, "y": 530},
        "size": {"width": 300, "height": 80},
        "shape": "store",
        "id": db_id,
        "zIndex": z,
        "type": "tm.Store",
        "data": {
            "name": "Backend Databases (MySQL/Redis/ES)",
            "description": "Users DB, Product Catalog, Orders DB, Payment Ledger, Redis Session Cache, Audit Logs.",
            "outOfScope": False,
            "reasonOutOfScope": "",
            "hasOpenThreats": False,
            "threats": [],
            "isALog": False,
            "storesCredentials": True,
            "isEncrypted": False,
            "isSigned": False,
        },
    })
    z += 1

    # ── Data Flows ──
    flows_def = [
        ("l0-customer",  sys_id,        "F1 HTTPS (Customer Requests)"),
        ("l0-seller",    sys_id,        "F2 HTTPS (Seller Portal Requests)"),
        ("l0-admin",     sys_id,        "F3 HTTPS/VPN (Admin Requests)"),
        (sys_id,         "l0-payment",  "F4 Payment API (Razorpay/PayU)"),
        ("l0-payment",   sys_id,        "F4 Webhook (Payment Callback)"),
        (sys_id,         "l0-logistics","F5 Shipping API (Dispatch/Tracking)"),
        (sys_id,         "l0-sms",      "F6 SMS/Email API (OTP/Alerts)"),
        (sys_id,         db_id,         "F7 SQL/Redis/ES (Internal Data)"),
    ]
    for src, tgt, name in flows_def:
        fid = str(uuid.uuid4())
        cells.append({
            "shape": "flow",
            "attrs": {
                ".marker-target": {"class": "marker-target hasNoOpenThreats isInScope"},
                ".connection": {"class": "connection hasNoOpenThreats isInScope"},
            },
            "id": fid,
            "zIndex": z,
            "type": "tm.Flow",
            "source": {"cell": src},
            "target": {"cell": tgt},
            "vertices": [],
            "data": {
                "name": name,
                "description": "",
                "outOfScope": False,
                "reasonOutOfScope": "",
                "hasOpenThreats": False,
                "isBidirectional": False,
                "isEncrypted": "HTTPS" in name or "VPN" in name,
                "isPublicNetwork": False,
                "protocol": "HTTPS" if "HTTPS" in name else "",
                "threats": [],
            },
        })
        z += 1

    return {
        "id": 0,
        "title": "DFD Level 0 - Flipkart Context Diagram",
        "diagramType": "STRIDE",
        "placeholder": "High-level context diagram showing external entities interacting with the Flipkart platform.",
        "thumbnail": "./public/content/images/thumbnail.stride.jpg",
        "version": "2.0.0",
        "cells": cells,
        "size": {"width": 1400, "height": 750},
    }


def build_threatdragon_json(tm7_path):
    """Parse .tm7 and produce Threat Dragon v2 JSON dict."""
    tree = ET.parse(tm7_path)
    root = tree.getroot()

    # Strip namespace from root tag to determine structure
    tag = root.tag
    if "}" in tag:
        tag = tag.split("}", 1)[1]

    # Extract metadata
    meta = root.find("{%s}MetaInformation" % NS["tm"])
    if meta is None:
        meta = root.find("MetaInformation")

    title = ""
    owner = ""
    description = ""
    if meta is not None:
        t = meta.find("{%s}ThreatModelName" % NS["tm"])
        if t is None:
            t = meta.find("ThreatModelName")
        title = t.text if t is not None and t.text else "Imported Threat Model"

        o = meta.find("{%s}Owner" % NS["tm"])
        if o is None:
            o = meta.find("Owner")
        owner = o.text if o is not None and o.text else ""

        d = meta.find("{%s}HighLevelSystemDescription" % NS["tm"])
        if d is None:
            d = meta.find("HighLevelSystemDescription")
        description = d.text if d is not None and d.text else ""

    # Parse drawing surfaces (diagrams)
    ds_list = root.find("{%s}DrawingSurfaceList" % NS["tm"])
    if ds_list is None:
        ds_list = root.find("DrawingSurfaceList")

    diagrams = []
    if ds_list is not None:
        for idx, ds in enumerate(ds_list.findall("{%s}DrawingSurfaceModel" % NS["tm"])):
            # Get diagram name
            ds_props = ds.find("{%s}Properties" % NS["abs"])
            diagram_name = find_property(ds_props, "Name") or f"Diagram {idx + 1}"

            elements, flows, boundaries = parse_elements(ds)

            # Parse and assign threats
            threats = parse_threats(root)
            assign_threats(threats, elements, flows)

            # Build cells array
            cells = []
            z_index = 1

            # Trust boundaries as curves
            for b_guid, b_data in boundaries.items():
                # Represent boundary as a boundary box curve
                x, y, w, h = b_data["x"], b_data["y"], b_data["w"], b_data["h"]
                cells.append({
                    "shape": "trust-boundary-box",
                    "id": b_guid,
                    "zIndex": -1,
                    "type": "tm.BoundaryBox",
                    "position": {"x": x, "y": y},
                    "size": {"width": w, "height": h},
                    "attrs": {},
                    "data": {
                        "name": b_data["name"],
                        "description": "",
                        "isTrustBoundary": True,
                    },
                })

            # Elements (actors, processes, stores)
            for e_guid, e_data in elements.items():
                has_open = any(t["status"] == "Open" for t in e_data["threats"])
                cell = {
                    "position": {"x": e_data["x"], "y": e_data["y"]},
                    "size": {"width": e_data["w"], "height": e_data["h"]},
                    "shape": e_data["shape"],
                    "id": e_guid,
                    "zIndex": z_index,
                    "type": e_data["type"],
                    "data": {
                        "name": e_data["name"],
                        "description": "",
                        "outOfScope": e_data.get("outOfScope", False),
                        "reasonOutOfScope": e_data.get("reasonOutOfScope", ""),
                        "hasOpenThreats": has_open,
                        "threats": e_data["threats"],
                    },
                }
                # Add type-specific properties
                if e_data["type"] == "tm.Actor":
                    cell["data"]["providesAuthentication"] = e_data.get("providesAuthentication", False)
                elif e_data["type"] == "tm.Process":
                    cell["data"]["privilegeLevel"] = e_data.get("privilegeLevel", "")
                elif e_data["type"] == "tm.Store":
                    cell["data"]["isALog"] = e_data.get("isALog", False)
                    cell["data"]["storesCredentials"] = e_data.get("storesCredentials", False)
                    cell["data"]["isEncrypted"] = e_data.get("isEncrypted", False)
                    cell["data"]["isSigned"] = e_data.get("isSigned", False)

                cells.append(cell)
                z_index += 1

            # Flows
            for f_guid, f_data in flows.items():
                has_open = any(t["status"] == "Open" for t in f_data["threats"])
                scope_class = "isInScope" if not f_data["outOfScope"] else "isOutOfScope"
                threat_class = "hasOpenThreats" if has_open else "hasNoOpenThreats"
                cell = {
                    "shape": "flow",
                    "attrs": {
                        ".marker-target": {"class": f"marker-target {threat_class} {scope_class}"},
                        ".connection": {"class": f"connection {threat_class} {scope_class}"},
                    },
                    "id": f_guid,
                    "zIndex": z_index,
                    "type": "tm.Flow",
                    "source": {"cell": f_data["sourceGuid"]},
                    "target": {"cell": f_data["targetGuid"]},
                    "vertices": f_data.get("vertices", []),
                    "data": {
                        "name": f_data["name"],
                        "description": "",
                        "outOfScope": f_data["outOfScope"],
                        "reasonOutOfScope": f_data.get("reasonOutOfScope", ""),
                        "hasOpenThreats": has_open,
                        "isBidirectional": False,
                        "isEncrypted": f_data.get("isEncrypted", False),
                        "isPublicNetwork": False,
                        "protocol": f_data.get("protocol", ""),
                        "threats": f_data["threats"],
                    },
                }
                cells.append(cell)
                z_index += 1

            diagrams.append({
                "id": idx,
                "title": diagram_name,
                "diagramType": "STRIDE",
                "placeholder": "New STRIDE diagram description",
                "thumbnail": "./public/content/images/thumbnail.stride.jpg",
                "version": "2.0.0",
                "cells": cells,
                "size": {"width": 2000, "height": 1200},
            })

    # Build DFD Level 0 context diagram and prepend it
    level0 = build_level0_diagram(elements_lookup if 'elements_lookup' in dir() else {})
    diagrams.insert(0, level0)
    # Re-number diagram ids
    for i, d in enumerate(diagrams):
        d["id"] = i

    td_json = {
        "version": "2.0.0",
        "summary": {
            "title": title,
            "owner": owner,
            "description": description,
            "id": 0,
        },
        "detail": {
            "contributors": [],
            "diagrams": diagrams,
        },
    }

    return td_json


def main():
    tm7_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "model_export.tm7"
    )
    if len(sys.argv) > 1:
        tm7_path = sys.argv[1]

    output_path = os.path.splitext(tm7_path)[0] + "_threatdragon_import.json"
    if len(sys.argv) > 2:
        output_path = sys.argv[2]

    print(f"Parsing: {tm7_path}")
    td_json = build_threatdragon_json(tm7_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(td_json, f, indent=2, ensure_ascii=False)

    n_diagrams = len(td_json["detail"]["diagrams"])
    n_cells = sum(len(d["cells"]) for d in td_json["detail"]["diagrams"])
    n_threats = 0
    for d in td_json["detail"]["diagrams"]:
        for c in d["cells"]:
            n_threats += len(c.get("data", {}).get("threats", []))

    print(f"Output:  {output_path}")
    print(f"  Diagrams: {n_diagrams}")
    print(f"  Cells:    {n_cells}")
    print(f"  Threats:  {n_threats}")
    print("Done! Import this file at: https://www.threatdragon.com/#/local/threatmodel/import")


if __name__ == "__main__":
    main()
