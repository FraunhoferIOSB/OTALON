from typing import Any, Dict

from asyncua import Client
from asyncua.tools import application_to_strings, endpoint_to_strings
from loguru import logger


async def uadiscover(ip_address: str = "127.0.0.1", port: int = 4840) -> Dict[str, Any]:
    """
    Perform OPC UA discovery against an endpoint and return found servers/endpoints.

    Parameters
    ----------
    ip_address : str
        Target IP address (default: loopback for safe tests).
    port : int
        Target TCP port (default: 4840).

    Returns
    -------
    dict
        {
          "servers": [ { ...server fields... }, ... ],
          "endpoints": [ { ...endpoint fields... }, ... ]
        }
    """
    url = f"opc.tcp://{ip_address}:{port}"
    client = Client(url)
    discover_dict: Dict[str, Any] = {"servers": [], "endpoints": []}

    try:
        logger.info("Performing discovery at {url}", url=url)
        for server in await client.connect_and_find_servers():
            server_info = {n: v for (n, v) in application_to_strings(server)}
            discover_dict["servers"].append(server_info)

        for ep in await client.connect_and_get_server_endpoints():
            endpoint_info = {n: v for (n, v) in endpoint_to_strings(ep)}
            discover_dict["endpoints"].append(endpoint_info)

    except Exception as e:
        logger.error(e)
    finally:
        # SCAN-020: tear down any half-open transport / watchdog task so
        # the owning child process can exit cleanly. ``connect_and_*``
        # helpers normally close their own socket, but a partial connect
        # against a slow server can leave the transport (and its watchdog)
        # alive — which keeps the child process running and strands the
        # scan at ``RUNNING``. Best-effort: a clean disconnect is a no-op.
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001 - best-effort cleanup only
            pass

    logger.info(
        "Discovered {len_discover_dict__servers} servers and {len_discover_dict__endpoints} endpoints.",
        len_discover_dict__servers=len(discover_dict["servers"]),
        len_discover_dict__endpoints=len(discover_dict["endpoints"]),
    )
    logger.debug("Discovery result: {}", discover_dict)
    return discover_dict
