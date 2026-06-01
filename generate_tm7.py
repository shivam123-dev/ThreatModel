"""
Generate a valid Microsoft Threat Modeling Tool (.tm7) file
for the Flipkart E-commerce Platform threat model.
Follows the exact WCF DataContract serialization XML format.
"""
import os
import uuid
import textwrap

NS_MODEL = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model"
NS_ABS = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts"
NS_KB = "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase"
NS_SER = "http://schemas.microsoft.com/2003/10/Serialization/"
NS_ARR = "http://schemas.microsoft.com/2003/10/Serialization/Arrays"
NS_XSD = "http://www.w3.org/2001/XMLSchema"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_IF = "http://schemas.datacontract.org/2004/07/ThreatModeling.Interfaces"

# Fixed GUIDs for elements
DIAGRAM_GUID = "d8c8aab1-5108-49c5-92a1-b214ba353477"

# External Entities
E1_GUID = "e1000001-1111-4e01-a001-e10000000001"  # Customer
E2_GUID = "e2000002-2222-4e02-a002-e20000000002"  # Seller
E3_GUID = "e3000003-3333-4e03-a003-e30000000003"  # Admin
E4_GUID = "e4000004-4444-4e04-a004-e40000000004"  # Payment GW
E5_GUID = "e5000005-5555-4e05-a005-e50000000005"  # Logistics
E6_GUID = "e6000006-6666-4e06-a006-e60000000006"  # SMS/Email

# Processes
P1_GUID = "b1010001-0001-4b01-ab01-010000000001"  # API Gateway
P2_GUID = "b2020002-0002-4b02-ab02-020000000002"  # Auth Service
P3_GUID = "b3030003-0003-4b03-ab03-030000000003"  # Product Service
P4_GUID = "b4040004-0004-4b04-ab04-040000000004"  # Seller Portal
P5_GUID = "b5050005-0005-4b05-ab05-050000000005"  # Cart/Checkout
P6_GUID = "b6060006-0006-4b06-ab06-060000000006"  # Order Mgmt
P7_GUID = "b7070007-0007-4b07-ab07-070000000007"  # Payment Service
P8_GUID = "b8080008-0008-4b08-ab08-080000000008"  # Notification

# Data Stores
D1_GUID = "c1d10001-d001-4c01-ac01-d10000000001"  # Users DB
D2_GUID = "c2d20002-d002-4c02-ac02-d20000000002"  # Product Catalog
D3_GUID = "c3d30003-d003-4c03-ac03-d30000000003"  # Orders DB
D4_GUID = "c4d40004-d004-4c04-ac04-d40000000004"  # Payment Ledger
D5_GUID = "c5d50005-d005-4c05-ac05-d50000000005"  # Redis
D6_GUID = "c6d60006-d006-4c06-ac06-d60000000006"  # Audit Logs

# Trust Boundaries
TB1_GUID = "aa0b0011-b001-4a01-aa01-bb0000000011"  # Microservices Network
TB2_GUID = "aa0b0012-b002-4a02-aa02-bb0000000012"  # PCI Zone

# Data Flows (Lines)
F1_GUID = "f1000001-0001-4f01-af01-f10000000001"   # Customer -> API GW
F2_GUID = "f2000002-0002-4f02-af02-f20000000002"   # Seller -> API GW
F3_GUID = "f3000003-0003-4f03-af03-f30000000003"   # Admin -> API GW
F_GW_CART_GUID = "f1100010-0010-4f10-af10-f11000000010"  # GW -> Cart
F_GW_AUTH_GUID = "f1100011-0011-4f11-af11-f11000000011"  # GW -> Auth
F_GW_PROD_GUID = "f1100012-0012-4f12-af12-f11000000012"  # GW -> Product
F_GW_SELL_GUID = "f1100013-0013-4f13-af13-f11000000013"  # GW -> Seller Portal
F_CART_ORD_GUID = "f1100014-0014-4f14-af14-f11000000014"  # Cart -> Order
F_ORD_PAY_GUID = "f1100015-0015-4f15-af15-f11000000015"  # Order -> Payment
F4_GUID = "f4000004-0004-4f04-af04-f40000000004"   # Payment -> PG
F4W_GUID = "f4000005-0005-4f05-af05-f40000000005"  # PG -> Payment (webhook)
F5_GUID = "f5000006-0006-4f06-af06-f50000000006"   # Order -> Logistics
F_ORD_NOT_GUID = "f1100016-0016-4f16-af16-f11000000016"  # Order -> Notification
F6_GUID = "f6000007-0007-4f07-af07-f60000000007"   # Notification -> SMS/Email
F_AUTH_DB_GUID = "fba00001-0001-4f01-af01-fb0000000001"  # Auth -> Users DB
F_PROD_DB_GUID = "fbb00002-0002-4f02-af02-fb0000000002"  # Product -> Catalog DB
F_ORD_DB_GUID = "fbc00003-0003-4f03-af03-fb0000000003"   # Order -> Orders DB
F_PAY_DB_GUID = "fbd00004-0004-4f04-af04-fb0000000004"   # Payment -> Ledger
F_AUTH_RED_GUID = "fbe00005-0005-4f05-af05-fb0000000005"  # Auth -> Redis
F_ORD_LOG_GUID = "fbf00006-0006-4f06-af06-fb0000000006"  # Order -> Audit Logs

z_counter = 0

def next_z():
    global z_counter
    z_counter += 1
    return f"i{z_counter}"


def xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")


def make_header_attr(display_name):
    return (
        f'<a:anyType i:type="b:HeaderDisplayAttribute" xmlns:b="{NS_KB}">'
        f'<b:DisplayName>{xml_escape(display_name)}</b:DisplayName>'
        f'<b:Name/>'
        f'<b:Value i:nil="true"/>'
        f'</a:anyType>'
    )


def make_string_attr(display_name, value, name=""):
    return (
        f'<a:anyType i:type="b:StringDisplayAttribute" xmlns:b="{NS_KB}">'
        f'<b:DisplayName>{xml_escape(display_name)}</b:DisplayName>'
        f'<b:Name>{name}</b:Name>'
        f'<b:Value i:type="c:string" xmlns:c="{NS_XSD}">{xml_escape(value)}</b:Value>'
        f'</a:anyType>'
    )


def make_bool_attr(display_name, name, value):
    val_str = "true" if value else "false"
    return (
        f'<a:anyType i:type="b:BooleanDisplayAttribute" xmlns:b="{NS_KB}">'
        f'<b:DisplayName>{xml_escape(display_name)}</b:DisplayName>'
        f'<b:Name>{name}</b:Name>'
        f'<b:Value i:type="c:boolean" xmlns:c="{NS_XSD}">{val_str}</b:Value>'
        f'</a:anyType>'
    )


def make_list_attr(display_name, name, values, selected_index=0):
    vals = "".join(f"<a:string>{xml_escape(v)}</a:string>" for v in values)
    return (
        f'<a:anyType i:type="b:ListDisplayAttribute" xmlns:b="{NS_KB}">'
        f'<b:DisplayName>{xml_escape(display_name)}</b:DisplayName>'
        f'<b:Name>{name}</b:Name>'
        f'<b:Value i:type="a:ArrayOfstring">{vals}</b:Value>'
        f'<b:SelectedIndex>{selected_index}</b:SelectedIndex>'
        f'</a:anyType>'
    )


def make_external_interactor(guid, name, oos=False, left=0, top=0, w=100, h=100):
    zid = next_z()
    props = (
        make_header_attr("Generic External Interactor")
        + make_string_attr("Name", name)
        + make_bool_attr("Out Of Scope", "71f3d9aa-b8ef-4e54-8126-607a1d903103", oos)
        + make_string_attr("Reason For Out Of Scope", "", "752473b6-52d4-4776-9a24-202153f7d579")
        + make_header_attr("Configurable Attributes")
        + make_list_attr("Authenticates Itself", "authenticatesItself",
                         ["Not Applicable", "No", "Yes"], 1)
        + make_list_attr("Type", "type",
                         ["Not Selected", "Code", "Human"], 0)
        + make_list_attr("Microsoft", "MS", ["No", "Yes"], 0)
    )
    return (
        f'<a:KeyValueOfguidanyType>'
        f'<a:Key>{guid}</a:Key>'
        f'<a:Value z:Id="{zid}" i:type="StencilRectangle">'
        f'<GenericTypeId xmlns="{NS_ABS}">GE.EI</GenericTypeId>'
        f'<Guid xmlns="{NS_ABS}">{guid}</Guid>'
        f'<Properties xmlns="{NS_ABS}">{props}</Properties>'
        f'<TypeId xmlns="{NS_ABS}">GE.EI</TypeId>'
        f'<Height xmlns="{NS_ABS}">{h}</Height>'
        f'<Left xmlns="{NS_ABS}">{left}</Left>'
        f'<StrokeDashArray i:nil="true" xmlns="{NS_ABS}"/>'
        f'<StrokeThickness xmlns="{NS_ABS}">1</StrokeThickness>'
        f'<Top xmlns="{NS_ABS}">{top}</Top>'
        f'<Width xmlns="{NS_ABS}">{w}</Width>'
        f'</a:Value>'
        f'</a:KeyValueOfguidanyType>'
    )


def make_process(guid, name, left=0, top=0, w=100, h=100):
    zid = next_z()
    props = (
        make_header_attr("Generic Process")
        + make_string_attr("Name", name)
        + make_bool_attr("Out Of Scope", "71f3d9aa-b8ef-4e54-8126-607a1d903103", False)
        + make_string_attr("Reason For Out Of Scope", "", "752473b6-52d4-4776-9a24-202153f7d579")
        + make_header_attr("Configurable Attributes")
        + make_list_attr("Code Type", "codeType",
                         ["Not Selected", "Managed", "Unmanaged"], 0)
        + make_list_attr("Implements or Uses an Authentication Mechanism", "implementsAuthenticationScheme",
                         ["No", "Yes"], 0)
        + make_list_attr("Implements or Uses an Authorization Mechanism", "implementsCustomAuthorizationMechanism",
                         ["No", "Yes"], 0)
        + make_list_attr("Sanitizes Input", "hasInputSanitizers",
                         ["Not Selected", "Yes", "No"], 0)
        + make_list_attr("Sanitizes Output", "hasOutputSanitizers",
                         ["Not Selected", "Yes", "No"], 0)
    )
    return (
        f'<a:KeyValueOfguidanyType>'
        f'<a:Key>{guid}</a:Key>'
        f'<a:Value z:Id="{zid}" i:type="StencilEllipse">'
        f'<GenericTypeId xmlns="{NS_ABS}">GE.P</GenericTypeId>'
        f'<Guid xmlns="{NS_ABS}">{guid}</Guid>'
        f'<Properties xmlns="{NS_ABS}">{props}</Properties>'
        f'<TypeId xmlns="{NS_ABS}">GE.P</TypeId>'
        f'<Height xmlns="{NS_ABS}">{h}</Height>'
        f'<Left xmlns="{NS_ABS}">{left}</Left>'
        f'<StrokeDashArray i:nil="true" xmlns="{NS_ABS}"/>'
        f'<StrokeThickness xmlns="{NS_ABS}">1</StrokeThickness>'
        f'<Top xmlns="{NS_ABS}">{top}</Top>'
        f'<Width xmlns="{NS_ABS}">{w}</Width>'
        f'</a:Value>'
        f'</a:KeyValueOfguidanyType>'
    )


def make_data_store(guid, name, left=0, top=0, w=100, h=80,
                    stores_creds=False, stores_logs=False, encrypted=False):
    zid = next_z()
    cred_idx = 1 if stores_creds else 0
    log_idx = 1 if stores_logs else 0
    enc_idx = 1 if encrypted else 0
    props = (
        make_header_attr("Generic Data Store")
        + make_string_attr("Name", name)
        + make_bool_attr("Out Of Scope", "71f3d9aa-b8ef-4e54-8126-607a1d903103", False)
        + make_string_attr("Reason For Out Of Scope", "", "752473b6-52d4-4776-9a24-202153f7d579")
        + make_header_attr("Configurable Attributes")
        + make_list_attr("Stores Credentials", "storesCredentials", ["No", "Yes"], cred_idx)
        + make_list_attr("Stores Log Data", "storesLogData", ["No", "Yes"], log_idx)
        + make_list_attr("Encrypted", "Encrypted", ["No", "Yes"], enc_idx)
        + make_list_attr("Signed", "Signed", ["No", "Yes"], 0)
        + make_list_attr("Write Access", "AccessType", ["No", "Yes"], 1)
        + make_list_attr("Removable Storage", "RemoveableStorage", ["No", "Yes"], 0)
    )
    return (
        f'<a:KeyValueOfguidanyType>'
        f'<a:Key>{guid}</a:Key>'
        f'<a:Value z:Id="{zid}" i:type="StencilParallelLines">'
        f'<GenericTypeId xmlns="{NS_ABS}">GE.DS</GenericTypeId>'
        f'<Guid xmlns="{NS_ABS}">{guid}</Guid>'
        f'<Properties xmlns="{NS_ABS}">{props}</Properties>'
        f'<TypeId xmlns="{NS_ABS}">GE.DS</TypeId>'
        f'<Height xmlns="{NS_ABS}">{h}</Height>'
        f'<Left xmlns="{NS_ABS}">{left}</Left>'
        f'<StrokeDashArray i:nil="true" xmlns="{NS_ABS}"/>'
        f'<StrokeThickness xmlns="{NS_ABS}">1</StrokeThickness>'
        f'<Top xmlns="{NS_ABS}">{top}</Top>'
        f'<Width xmlns="{NS_ABS}">{w}</Width>'
        f'</a:Value>'
        f'</a:KeyValueOfguidanyType>'
    )


def make_trust_boundary(guid, name, left=0, top=0, w=300, h=300):
    zid = next_z()
    props = (
        make_header_attr("Generic Trust Border Boundary")
        + make_string_attr("Name", name)
    )
    return (
        f'<a:KeyValueOfguidanyType>'
        f'<a:Key>{guid}</a:Key>'
        f'<a:Value z:Id="{zid}" i:type="BorderBoundary">'
        f'<GenericTypeId xmlns="{NS_ABS}">GE.TB.B</GenericTypeId>'
        f'<Guid xmlns="{NS_ABS}">{guid}</Guid>'
        f'<Properties xmlns="{NS_ABS}">{props}</Properties>'
        f'<TypeId xmlns="{NS_ABS}">GE.TB.B</TypeId>'
        f'<Height xmlns="{NS_ABS}">{h}</Height>'
        f'<Left xmlns="{NS_ABS}">{left}</Left>'
        f'<StrokeDashArray i:nil="true" xmlns="{NS_ABS}"/>'
        f'<StrokeThickness xmlns="{NS_ABS}">1</StrokeThickness>'
        f'<Top xmlns="{NS_ABS}">{top}</Top>'
        f'<Width xmlns="{NS_ABS}">{w}</Width>'
        f'</a:Value>'
        f'</a:KeyValueOfguidanyType>'
    )


def make_connector(guid, name, src_guid, tgt_guid, src_x, src_y, tgt_x, tgt_y,
                   port_src="East", port_tgt="West"):
    zid = next_z()
    hx = (src_x + tgt_x) // 2
    hy = (src_y + tgt_y) // 2
    props = (
        make_header_attr("Generic Data Flow")
        + make_string_attr("Name", name)
        + make_bool_attr("Out Of Scope", "71f3d9aa-b8ef-4e54-8126-607a1d903103", False)
        + make_string_attr("Reason For Out Of Scope", "", "752473b6-52d4-4776-9a24-202153f7d579")
        + make_header_attr("Configurable Attributes")
        + make_list_attr("Source Authenticated", "authenticatesSource",
                         ["Not Selected", "No", "Yes"], 0)
        + make_list_attr("Destination Authenticated", "authenticatesDestination",
                         ["No", "Yes"], 0)
        + make_list_attr("Provides Confidentiality", "providesConfidentiality",
                         ["No", "Yes"], 0)
        + make_list_attr("Provides Integrity", "providesIntegrity",
                         ["No", "Yes"], 0)
    )
    return (
        f'<a:KeyValueOfguidanyType>'
        f'<a:Key>{guid}</a:Key>'
        f'<a:Value z:Id="{zid}" i:type="Connector">'
        f'<GenericTypeId xmlns="{NS_ABS}">GE.DF</GenericTypeId>'
        f'<Guid xmlns="{NS_ABS}">{guid}</Guid>'
        f'<Properties xmlns="{NS_ABS}">{props}</Properties>'
        f'<TypeId xmlns="{NS_ABS}">GE.DF</TypeId>'
        f'<HandleX xmlns="{NS_ABS}">{hx}</HandleX>'
        f'<HandleY xmlns="{NS_ABS}">{hy}</HandleY>'
        f'<PortSource xmlns="{NS_ABS}">{port_src}</PortSource>'
        f'<PortTarget xmlns="{NS_ABS}">{port_tgt}</PortTarget>'
        f'<SourceGuid xmlns="{NS_ABS}">{src_guid}</SourceGuid>'
        f'<SourceX xmlns="{NS_ABS}">{src_x}</SourceX>'
        f'<SourceY xmlns="{NS_ABS}">{src_y}</SourceY>'
        f'<TargetGuid xmlns="{NS_ABS}">{tgt_guid}</TargetGuid>'
        f'<TargetX xmlns="{NS_ABS}">{tgt_x}</TargetX>'
        f'<TargetY xmlns="{NS_ABS}">{tgt_y}</TargetY>'
        f'</a:Value>'
        f'</a:KeyValueOfguidanyType>'
    )


def make_threat(threat_id, title, category, description, priority,
                diagram_guid, flow_guid, src_guid, tgt_guid, flow_name,
                state="Needs Investigation", state_info="", type_id="custom"):
    key = f"{type_id}{src_guid}{flow_guid}{tgt_guid}"
    interaction_key = f"{src_guid}:{flow_guid}:{tgt_guid}"
    return (
        f'<a:KeyValueOfstringThreatpc_P0_PhOB>'
        f'<a:Key>{key}</a:Key>'
        f'<a:Value xmlns:b="{NS_KB}">'
        f'<b:ChangedBy>Student</b:ChangedBy>'
        f'<b:DrawingSurfaceGuid>{diagram_guid}</b:DrawingSurfaceGuid>'
        f'<b:FlowGuid>{flow_guid}</b:FlowGuid>'
        f'<b:Id>{threat_id}</b:Id>'
        f'<b:InteractionKey>{interaction_key}</b:InteractionKey>'
        f'<b:InteractionString i:nil="true"/>'
        f'<b:ModifiedAt>2026-05-31T00:00:00</b:ModifiedAt>'
        f'<b:Priority>{xml_escape(priority)}</b:Priority>'
        f'<b:Properties>'
        f'<a:KeyValueOfstringstring><a:Key>Title</a:Key><a:Value>{xml_escape(title)}</a:Value></a:KeyValueOfstringstring>'
        f'<a:KeyValueOfstringstring><a:Key>UserThreatCategory</a:Key><a:Value>{xml_escape(category)}</a:Value></a:KeyValueOfstringstring>'
        f'<a:KeyValueOfstringstring><a:Key>UserThreatShortDescription</a:Key><a:Value>{xml_escape(description[:200])}</a:Value></a:KeyValueOfstringstring>'
        f'<a:KeyValueOfstringstring><a:Key>UserThreatDescription</a:Key><a:Value>{xml_escape(description)}</a:Value></a:KeyValueOfstringstring>'
        f'<a:KeyValueOfstringstring><a:Key>InteractionString</a:Key><a:Value>{xml_escape(flow_name)}</a:Value></a:KeyValueOfstringstring>'
        f'<a:KeyValueOfstringstring><a:Key>Priority</a:Key><a:Value>{xml_escape(priority)}</a:Value></a:KeyValueOfstringstring>'
        f'</b:Properties>'
        f'<b:SourceGuid>{src_guid}</b:SourceGuid>'
        f'<b:State>{state}</b:State>'
        f'<b:StateInformation>{xml_escape(state_info)}</b:StateInformation>'
        f'<b:TargetGuid>{tgt_guid}</b:TargetGuid>'
        f'<b:Title i:nil="true"/>'
        f'<b:TypeId>{type_id}</b:TypeId>'
        f'<b:Upgraded>false</b:Upgraded>'
        f'<b:UserThreatCategory i:nil="true"/>'
        f'<b:UserThreatDescription i:nil="true"/>'
        f'<b:UserThreatShortDescription i:nil="true"/>'
        f'<b:Wide>false</b:Wide>'
        f'</a:Value>'
        f'</a:KeyValueOfstringThreatpc_P0_PhOB>'
    )


def build_borders():
    """Build all Borders (stencils + trust boundaries) for the diagram."""
    parts = []

    # External Entities
    parts.append(make_external_interactor(E1_GUID, "E1 Customer (Mobile/Web)", False, 30, 50, 150, 80))
    parts.append(make_external_interactor(E2_GUID, "E2 Seller", False, 30, 250, 150, 80))
    parts.append(make_external_interactor(E3_GUID, "E3 Flipkart Admin", False, 30, 450, 150, 80))
    parts.append(make_external_interactor(E4_GUID, "E4 Payment Gateway (Razorpay/PayU)", True, 850, 50, 180, 80))
    parts.append(make_external_interactor(E5_GUID, "E5 Logistics (Ekart)", True, 850, 250, 180, 80))
    parts.append(make_external_interactor(E6_GUID, "E6 SMS/Email Provider", True, 850, 450, 180, 80))

    # Trust Boundaries
    parts.append(make_trust_boundary(TB1_GUID, "Flipkart Microservices Network", 200, 20, 630, 580))
    parts.append(make_trust_boundary(TB2_GUID, "PCI DSS Zone", 620, 30, 200, 150))

    # Processes (inside trust boundary)
    parts.append(make_process(P1_GUID, "P1 API Gateway (Kong/Zuul)", 220, 180, 130, 80))
    parts.append(make_process(P2_GUID, "P2 User and Auth Service", 220, 330, 130, 80))
    parts.append(make_process(P3_GUID, "P3 Product and Search Service", 220, 480, 130, 80))
    parts.append(make_process(P4_GUID, "P4 Seller Portal Service", 380, 480, 130, 80))
    parts.append(make_process(P5_GUID, "P5 Cart and Checkout Service", 380, 180, 130, 80))
    parts.append(make_process(P6_GUID, "P6 Order Management Service", 380, 330, 130, 80))
    parts.append(make_process(P7_GUID, "P7 Payment Service", 640, 50, 160, 80))
    parts.append(make_process(P8_GUID, "P8 Notification Service", 540, 450, 130, 80))

    # Data Stores
    parts.append(make_data_store(D1_GUID, "D1 Users DB (MySQL)", 540, 180, 150, 60, stores_creds=True))
    parts.append(make_data_store(D2_GUID, "D2 Product Catalog (MySQL+ES)", 540, 260, 150, 60))
    parts.append(make_data_store(D3_GUID, "D3 Orders DB (MySQL)", 540, 340, 150, 60))
    parts.append(make_data_store(D4_GUID, "D4 Payment Ledger (MySQL)", 640, 150, 150, 60, encrypted=True))
    parts.append(make_data_store(D5_GUID, "D5 Redis Session Cache", 380, 560, 130, 50))
    parts.append(make_data_store(D6_GUID, "D6 Audit Logs (ELK)", 540, 540, 150, 50, stores_logs=True))

    return "".join(parts)


def build_lines():
    """Build all Lines (connectors/data flows) for the diagram."""
    flows = [
        # External to API Gateway
        (F1_GUID, "F1 HTTPS (Customer Requests)", E1_GUID, P1_GUID, 180, 90, 220, 220, "East", "West"),
        (F2_GUID, "F2 HTTPS (Seller Portal Requests)", E2_GUID, P1_GUID, 180, 290, 220, 240, "East", "West"),
        (F3_GUID, "F3 HTTPS/VPN (Admin Requests)", E3_GUID, P1_GUID, 180, 490, 220, 250, "East", "South"),
        # API Gateway to internal services
        (F_GW_CART_GUID, "Route: Cart/Checkout API", P1_GUID, P5_GUID, 350, 220, 380, 220, "East", "West"),
        (F_GW_AUTH_GUID, "Route: Auth/Login API", P1_GUID, P2_GUID, 285, 260, 285, 330, "South", "North"),
        (F_GW_PROD_GUID, "Route: Product/Search API", P1_GUID, P3_GUID, 260, 260, 260, 480, "South", "North"),
        (F_GW_SELL_GUID, "Route: Seller Portal API", P1_GUID, P4_GUID, 320, 260, 380, 520, "South", "North"),
        # Internal flows
        (F_CART_ORD_GUID, "F8 Place Order (gRPC/REST)", P5_GUID, P6_GUID, 445, 260, 445, 330, "South", "North"),
        (F_ORD_PAY_GUID, "F9 Payment Request", P6_GUID, P7_GUID, 510, 360, 640, 90, "East", "West"),
        # External outbound
        (F4_GUID, "F4 Payment API (Razorpay)", P7_GUID, E4_GUID, 800, 90, 850, 90, "East", "West"),
        (F4W_GUID, "F4 Webhook (Payment Callback)", E4_GUID, P7_GUID, 850, 110, 800, 110, "West", "East"),
        (F5_GUID, "F5 Shipping API (Dispatch/Tracking)", P6_GUID, E5_GUID, 510, 370, 850, 290, "East", "West"),
        (F_ORD_NOT_GUID, "Kafka Event (Order Status)", P6_GUID, P8_GUID, 445, 410, 540, 480, "South", "North"),
        (F6_GUID, "F6 SMS/Email API (OTP/Alerts)", P8_GUID, E6_GUID, 670, 490, 850, 490, "East", "West"),
        # Services to data stores
        (F_AUTH_DB_GUID, "SQL (User CRUD, Password Hash)", P2_GUID, D1_GUID, 350, 370, 540, 210, "East", "West"),
        (F_PROD_DB_GUID, "SQL/ES (Product Search)", P3_GUID, D2_GUID, 350, 520, 540, 290, "East", "West"),
        (F_ORD_DB_GUID, "SQL (Order CRUD)", P6_GUID, D3_GUID, 510, 370, 540, 370, "East", "West"),
        (F_PAY_DB_GUID, "SQL (Payment Records)", P7_GUID, D4_GUID, 720, 130, 720, 150, "South", "North"),
        (F_AUTH_RED_GUID, "Redis (JWT Session Store)", P2_GUID, D5_GUID, 350, 400, 380, 560, "South", "North"),
        (F_ORD_LOG_GUID, "Logstash (Audit Events)", P6_GUID, D6_GUID, 480, 410, 540, 560, "South", "North"),
    ]
    parts = []
    for args in flows:
        parts.append(make_connector(*args))
    return "".join(parts)


def build_threats():
    """Build all 20 STRIDE threat instances."""
    threats_data = [
        (1, "T01 - API Gateway Request Smuggling", "Tampering",
         "Attacker crafts ambiguous HTTP requests to bypass Kong/Zuul gateway routing rules and reach internal microservices directly, potentially accessing admin-only endpoints.",
         "High", F1_GUID, E1_GUID, P1_GUID, "F1 HTTPS (Customer Requests)",
         "Likelihood: Medium | Impact: High | Mitigation: Normalize and validate HTTP requests at gateway, disable HTTP/1.0, enforce strict parsing, and run regular smuggling tests.", "T1"),

        (2, "T02 - OTP Brute-Force on Flipkart Login", "Spoofing",
         "Flipkart uses OTP-based mobile login. Attacker automates rapid OTP guesses (4-6 digit) against /api/auth/verify-otp to take over accounts without knowing the password.",
         "High", F_GW_AUTH_GUID, P1_GUID, P2_GUID, "Route: Auth/Login API",
         "Likelihood: High | Impact: High | Mitigation: Rate-limit OTP attempts per phone number, enforce exponential backoff, use CAPTCHA after failed attempts, and expire OTPs within 60 seconds.", "S1"),

        (3, "T03 - Credential Stuffing on Email/Password Login", "Spoofing",
         "Attacker uses leaked credential databases to automate login attempts against Flipkart accounts that still use email/password.",
         "High", F_GW_AUTH_GUID, P1_GUID, P2_GUID, "Route: Auth/Login API",
         "Likelihood: High | Impact: High | Mitigation: Breached-password detection, adaptive MFA, device fingerprinting, and account lockout after repeated failures.", "S2"),

        (4, "T04 - Price/Coupon Tampering During Checkout", "Tampering",
         "Attacker intercepts Flipkart checkout API calls and modifies cart total, discount amount, or coupon code in the request body to pay less than the actual price.",
         "High", F_GW_CART_GUID, P1_GUID, P5_GUID, "Route: Cart/Checkout API",
         "Likelihood: Medium | Impact: High | Mitigation: Server-side price recalculation from catalog DB, signed cart tokens, coupon validation on backend, and re-verify totals before payment.", "T2"),

        (5, "T05 - IDOR on Order Details and Address Endpoints", "Elevation Of Privilege",
         "Authenticated customer changes orderId or addressId in /api/orders/{id} or /api/address/{id} to view or modify another user's order details, delivery address, or phone number.",
         "High", F_ORD_DB_GUID, P6_GUID, D3_GUID, "SQL (Order CRUD)",
         "Likelihood: High | Impact: High | Mitigation: Enforce object-level authorization: verify that the requesting user owns the resource on every API call. Use UUIDs instead of sequential IDs.", "E1"),

        (6, "T06 - Fake Seller Registration and Listing Fraud", "Spoofing",
         "Attacker registers as a seller with stolen GST/PAN details, lists counterfeit or non-existent products at attractive prices, collects payments, and never ships goods.",
         "High", F2_GUID, E2_GUID, P1_GUID, "F2 HTTPS (Seller Portal Requests)",
         "Likelihood: Medium | Impact: High | Mitigation: KYC verification (video, bank account, GST validation), seller escrow with delayed payouts, and automated fraud scoring.", "S3"),

        (7, "T07 - Razorpay/PayU Webhook Spoofing", "Spoofing",
         "Attacker forges a payment success webhook to /api/payment/callback causing Flipkart to mark an unpaid order as paid and ship the product.",
         "High", F4W_GUID, E4_GUID, P7_GUID, "F4 Webhook (Payment Callback)",
         "Likelihood: Medium | Impact: High | Mitigation: Verify webhook HMAC signatures using shared secret, validate payment amount matches order total, and perform server-to-server verification with Razorpay Orders API.", "S4"),

        (8, "T08 - Mass User PII Exposure (Phone, Aadhaar, Address)", "Information Disclosure",
         "Database breach or misconfigured backup exposes 400M+ user records including phone numbers, delivery addresses, and saved payment methods to attackers.",
         "High", F_AUTH_DB_GUID, P2_GUID, D1_GUID, "SQL (User CRUD, Password Hash)",
         "Likelihood: Medium | Impact: High | Mitigation: Encrypt sensitive columns (AES-256), use envelope encryption with AWS KMS, restrict DB access via IAM, encrypt backups, and implement data masking for non-production environments.", "I1"),

        (9, "T09 - SQL Injection on Product Search/Filter", "Tampering",
         "Attacker injects SQL via search query, price range filter, or sort parameter on /api/products/search to extract product catalog data, seller information, or pricing strategies.",
         "High", F_PROD_DB_GUID, P3_GUID, D2_GUID, "SQL/ES (Product Search)",
         "Likelihood: Medium | Impact: High | Mitigation: Use parameterized queries for MySQL, validate Elasticsearch query DSL, sanitize all filter inputs, and use ORM (Hibernate) consistently.", "T3"),

        (10, "T10 - Flash Sale DDoS (Big Billion Days)", "Denial Of Service",
         "During Flipkart Big Billion Days sale, attackers or scalper bots flood the cart/checkout APIs with millions of requests to exhaust inventory holds and crash the checkout pipeline.",
         "High", F_GW_CART_GUID, P1_GUID, P5_GUID, "Route: Cart/Checkout API",
         "Likelihood: High | Impact: High | Mitigation: CDN-level DDoS protection (Akamai), rate limiting per user/IP, queue-based checkout (virtual waiting room), bot detection via device fingerprinting, and auto-scaling cart microservice.", "D1"),

        (11, "T11 - Stored XSS in Product Reviews and Q&A", "Tampering",
         "Attacker posts a product review or Q&A answer containing JavaScript that executes in other customers' browsers, stealing session tokens or redirecting to phishing pages.",
         "Medium", F_GW_PROD_GUID, P1_GUID, P3_GUID, "Route: Product/Search API",
         "Likelihood: Medium | Impact: Medium | Mitigation: Server-side HTML sanitization (OWASP Java HTML Sanitizer), output encoding, strict CSP headers, and review moderation pipeline.", "T4"),

        (12, "T12 - Payment Card Data Exposure (PCI DSS Violation)", "Information Disclosure",
         "Saved card details (CVV, full PAN) stored in plaintext in payment ledger or application logs, leading to mass card fraud if breached.",
         "High", F_PAY_DB_GUID, P7_GUID, D4_GUID, "SQL (Payment Records)",
         "Likelihood: Low | Impact: High | Mitigation: Tokenize card data via Razorpay vault, never store CVV, truncate PAN to last 4 digits, achieve PCI DSS Level 1 compliance, and scan logs for accidental card data leakage.", "I2"),

        (13, "T13 - Admin Account Phishing and Session Hijack", "Spoofing",
         "Attacker sends targeted phishing email to Flipkart admin, stealing credentials or admin session cookie to access seller payout controls, catalog management, and user data.",
         "High", F3_GUID, E3_GUID, P1_GUID, "F3 HTTPS/VPN (Admin Requests)",
         "Likelihood: Medium | Impact: High | Mitigation: Hardware security keys (FIDO2) for admin login, admin-only VPN, session binding to IP/device, privileged access management (PAM), and just-in-time access elevation.", "S5"),

        (14, "T14 - Seller Inventory and Price Manipulation", "Tampering",
         "Compromised seller account or API key is used to bulk-update product prices to 1 INR or inflate stock counts to win Buy Box placement unfairly.",
         "Medium", F_GW_SELL_GUID, P1_GUID, P4_GUID, "Route: Seller Portal API",
         "Likelihood: Medium | Impact: Medium | Mitigation: Anomaly detection on price/stock changes (>50% deviation triggers review), seller API rate limits, and mandatory 2FA for bulk updates.", "T5"),

        (15, "T15 - Delivery Dispute: Customer Denies Receipt", "Repudiation",
         "Customer claims product was not delivered despite successful handoff. Without signed proof of delivery, Flipkart must refund and absorb the loss.",
         "Medium", F5_GUID, P6_GUID, E5_GUID, "F5 Shipping API (Dispatch/Tracking)",
         "Likelihood: Medium | Impact: Medium | Mitigation: OTP-verified delivery, photo proof of delivery via Ekart app, GPS-stamped delivery events, and centralized dispute audit trail.", "R1"),

        (16, "T16 - Audit Log Tampering or Deletion", "Repudiation",
         "Insider or attacker with DB access deletes or modifies audit logs to cover tracks after unauthorized data access or fraudulent refund processing.",
         "Medium", F_ORD_LOG_GUID, P6_GUID, D6_GUID, "Logstash (Audit Events)",
         "Likelihood: Low | Impact: Medium | Mitigation: Write-once append-only log storage, ship logs to centralized SIEM (Splunk/ELK) in real-time, cryptographic log integrity (hash chains), and separate log-admin role.", "R2"),

        (17, "T17 - Session Token Leakage from Mobile App", "Information Disclosure",
         "Flipkart Android/iOS app stores JWT or session token in SharedPreferences/NSUserDefaults without encryption. Malware or rooted device extracts tokens for account takeover.",
         "High", F1_GUID, E1_GUID, P1_GUID, "F1 HTTPS (Customer Requests)",
         "Likelihood: Medium | Impact: High | Mitigation: Store tokens in Android Keystore / iOS Keychain, use certificate pinning, detect rooted/jailbroken devices, and bind tokens to device fingerprint.", "I3"),

        (18, "T18 - Cart Bombing / Inventory Hold Abuse", "Tampering",
         "Attacker adds limited-stock flash sale items to thousands of carts via automated scripts, holding inventory without purchasing to deny legitimate buyers access.",
         "Medium", F_GW_CART_GUID, P1_GUID, P5_GUID, "Route: Cart/Checkout API",
         "Likelihood: Medium | Impact: Medium | Mitigation: Short cart reservation timeouts (5 min for flash sales), per-user quantity limits, bot detection (CAPTCHA on add-to-cart during sales), and inventory release on timeout.", "T6"),

        (19, "T19 - Mobile App API Key Extraction", "Spoofing",
         "Attacker reverse-engineers Flipkart APK to extract API keys, client secrets, or hardcoded credentials used for internal service authentication.",
         "Medium", F1_GUID, E1_GUID, P1_GUID, "F1 HTTPS (Customer Requests)",
         "Likelihood: Medium | Impact: Medium | Mitigation: Use OAuth2 device flow instead of embedded secrets, obfuscate APK (ProGuard/R8), rotate API keys frequently, and monitor for anomalous API key usage patterns.", "S6"),

        (20, "T20 - Refund Fraud with Insufficient Evidence", "Repudiation",
         "Customer or seller disputes a transaction. Without signed receipts, delivery proof, or immutable payment logs, Flipkart cannot prove the transaction occurred, leading to chargebacks.",
         "Medium", F_ORD_PAY_GUID, P6_GUID, P7_GUID, "F9 Payment Request",
         "Likelihood: Medium | Impact: Medium | Mitigation: Store signed payment receipts, maintain immutable transaction ledger, integrate Razorpay dispute evidence API, and implement automated chargeback response.", "R3"),
    ]

    parts = []
    for (tid, title, cat, desc, prio, flow_guid, src_guid, tgt_guid, flow_name,
         state_info, type_id) in threats_data:
        parts.append(make_threat(
            tid, title, cat, desc, prio,
            DIAGRAM_GUID, flow_guid, src_guid, tgt_guid, flow_name,
            state="Needs Investigation", state_info=state_info, type_id=type_id
        ))
    return "".join(parts)


def build_knowledge_base():
    """Extract the full KnowledgeBase from Sample_Threat_Model.tm7 (Azure template)."""
    sample_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "Sample_Threat_Model.tm7")
    with open(sample_path, "r", encoding="utf-8") as f:
        sample = f.read()
    kb_start = sample.index("<KnowledgeBase")
    kb_end = sample.index("</KnowledgeBase>") + len("</KnowledgeBase>")
    return sample[kb_start:kb_end]


def generate_tm7():
    global z_counter
    z_counter = 0

    borders = build_borders()
    lines = build_lines()
    threats = build_threats()
    kb = build_knowledge_base()

    drawing_surface_zid = next_z()

    xml = (
        f'<ThreatModel xmlns="{NS_MODEL}" xmlns:i="{NS_XSI}">'

        # DrawingSurfaceList
        f'<DrawingSurfaceList>'
        f'<DrawingSurfaceModel z:Id="{drawing_surface_zid}" xmlns:z="{NS_SER}">'

        # DrawingSurface metadata
        f'<GenericTypeId xmlns="{NS_ABS}">DRAWINGSURFACE</GenericTypeId>'
        f'<Guid xmlns="{NS_ABS}">{DIAGRAM_GUID}</Guid>'
        f'<Properties xmlns="{NS_ABS}" xmlns:a="{NS_ARR}">'
        f'<a:anyType i:type="b:HeaderDisplayAttribute" xmlns:b="{NS_KB}">'
        f'<b:DisplayName>Diagram</b:DisplayName><b:Name/><b:Value i:nil="true"/>'
        f'</a:anyType>'
        f'<a:anyType i:type="b:StringDisplayAttribute" xmlns:b="{NS_KB}">'
        f'<b:DisplayName>Name</b:DisplayName><b:Name/>'
        f'<b:Value i:type="c:string" xmlns:c="{NS_XSD}">Flipkart E-commerce Platform - DFD Level 1</b:Value>'
        f'</a:anyType>'
        f'</Properties>'
        f'<TypeId xmlns="{NS_ABS}">DRAWINGSURFACE</TypeId>'

        # Borders (all stencils + trust boundaries)
        f'<Borders xmlns:a="{NS_ARR}">{borders}</Borders>'

        # Lines (all data flows)
        f'<Lines xmlns:a="{NS_ARR}">{lines}</Lines>'

        f'<Zoom>1</Zoom>'
        f'</DrawingSurfaceModel>'
        f'</DrawingSurfaceList>'

        # MetaInformation
        f'<MetaInformation>'
        f'<Assumptions>1. All external communication uses TLS 1.2+. 2. API Gateway is the single entry point. 3. Internal services on private network. 4. Payment via Razorpay/PayU. 5. Ekart for logistics. 6. Mobile apps and web browsers as clients.</Assumptions>'
        f'<Contributors>Secure Software Engineering - BITS Pilani Sem 3</Contributors>'
        f'<ExternalDependencies>Razorpay/PayU, Ekart Logistics, SMS Provider (MSG91), Email Provider (SendGrid), AWS/GCP Cloud, Akamai CDN</ExternalDependencies>'
        f'<HighLevelSystemDescription>Microservices-based e-commerce platform modeled on Flipkart architecture: API Gateway (Kong/Zuul), User/Auth Service with OTP login, Product/Search Service with Elasticsearch, Cart/Checkout, Order Management, Payment Service (Razorpay/PayU), Seller Portal, Notification Service, and Ekart Logistics integration.</HighLevelSystemDescription>'
        f'<Owner>Student</Owner>'
        f'<Reviewer/>'
        f'<ThreatModelName>Flipkart E-commerce Platform - STRIDE Threat Model</ThreatModelName>'
        f'</MetaInformation>'

        # Notes
        f'<Notes/>'

        # ThreatInstances
        f'<ThreatInstances xmlns:a="{NS_ARR}">{threats}</ThreatInstances>'

        # KnowledgeBase
        f'{kb}'

        # Profile
        f'<Profile><PromptedKb xmlns=""/></Profile>'

        f'</ThreatModel>'
    )

    return xml


if __name__ == "__main__":
    import os
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_export.tm7")
    xml_content = generate_tm7()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml_content)
    print(f"Generated {output_path}")
    print(f"File size: {os.path.getsize(output_path):,} bytes")
