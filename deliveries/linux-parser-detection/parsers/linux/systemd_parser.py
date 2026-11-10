
from core.normalized_event import NormalizedEvent


def parse_systemd_services(
    file_path,
    case_id="CASE-001",
    host_id="LINUX-001"
):
    events = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    service_data = {}
    block_start = None

    def create_event(data, start_line, end_line):
        service_name = data.get("Id")

        # A service without an Id cannot be identified reliably.
        if not service_name:
            return None

        active_state = data.get("ActiveState")
        sub_state = data.get("SubState")

        if active_state and sub_state:
            status = f"{active_state}/{sub_state}"
        else:
            status = active_state or sub_state

        unit_path = data.get("FragmentPath")

        return NormalizedEvent(
            event_id=f"LINUX-SYSTEMD-{start_line}",
            case_id=case_id,
            host_id=host_id,
            platform="linux",
            severity="info",
            message=f"Systemd service information collected: {service_name}",

            event_type="systemd_service",
            source="systemd_services.txt",
            evidence_reference=(
                f"systemd_services.txt:lines-{start_line}-{end_line}"
            ),

            metadata={
                "service_name": service_name,
                "status": status,
                "active_state": active_state,
                "sub_state": sub_state,
                "load_state": data.get("LoadState"),
                "unit_path": unit_path,
                "line_number": start_line
            }
        )

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()

        if not line:
            if service_data:
                event = create_event(
                    service_data,
                    block_start,
                    line_number - 1
                )

                if event:
                    events.append(event)

                service_data = {}
                block_start = None

            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)

        if block_start is None:
            block_start = line_number

        service_data[key] = value

    # Process the final block if the file doesn't end with a blank line.
    if service_data:
        event = create_event(
            service_data,
            block_start,
            len(lines)
        )

        if event:
            events.append(event)

    return events
