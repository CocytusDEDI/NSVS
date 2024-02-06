from models import (full_scan, parse_ipconfig, info_to_cpe, get_cpe_cves, ParsingError, SCAN_RESULTS_TYPE,
                    DEFAULT_CVE_LIMIT, DEFAULT_CPE_LIMIT)
import socket
import json
import tomli

__all__ = ["handle_scan", "create_preset", "delete_preset", "get_interfaces", "get_presets", "SCAN_RESULTS_TYPE",
           "NUMBERS"]

try:
    with open("config.toml", "rb") as config_file:
        config = tomli.load(config_file)
except (tomli.TOMLDecodeError, FileNotFoundError):
    config = {}

NUMBERS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
DEFAULT_PORTS = config["api"]["DEFAULT_PORTS"] \
    if (config.get("api", {}).get("DEFAULT_PORTS")) else [20, 53, 80, 110, 143, 443, 514, 3389]


def correct_file_error(error) -> None:
    """
    Makes files parse-able by replacing contents.
    :param error: Must be FileNotFoundError, json.decoder.JSONDecodeError, ParsingError or any subclass of them.
    :return: None.
    """
    if isinstance(error, FileNotFoundError):
        # Creates the file and fills it with an empty list.
        file = open(error.filename, "x")
        if error.filename == "presets.json":
            file.write("[]")
        file.close()
    elif isinstance(error, json.decoder.JSONDecodeError):
        # Deletes the file's contents and replaces it with an empty list.
        file = open(error.doc, "w")
        if error.doc == "presets.json":
            file.write("[]")
        file.close()
    elif isinstance(error, ParsingError):
        raise NotImplementedError("correct_file_error() can't fix ParsingError currently, "
                                  "nmap-service-probes.txt is corrupt")
        # Idea: Copy nmap-service-probes.txt from server if available, possibly same version from projects GitHub to
        # avoid unexpected errors.


def add_cpe_results(scan_results: SCAN_RESULTS_TYPE, limit: int = DEFAULT_CPE_LIMIT) -> SCAN_RESULTS_TYPE:
    """
    Adds a cpe to all port data that it can.
    :param scan_results: The data provided from full_scan() in models.py.
    :param limit: How many cpes to search per port_data, only the one with the correct version is added.
    :return: The scan results with cpes added to every port data it can.
    """
    for interface in list(scan_results):
        for ip_index in range(len(scan_results[interface])):
            for port_data_index in range(len(scan_results[interface][ip_index]["ports_data"])):
                if scan_results[interface][ip_index]["ports_data"][port_data_index].get("vendor_product_name") is None:
                    continue
                try:
                    cpe = info_to_cpe(
                        scan_results[interface][ip_index]["ports_data"][port_data_index]["vendor_product_name"],
                        scan_results[interface][ip_index]["ports_data"][port_data_index].get("version", None),
                        limit)
                except socket.error:
                    cpe = None
                if cpe is not None:
                    scan_results[interface][ip_index]["ports_data"][port_data_index]["cpe"] = cpe
    return scan_results


def add_cve_results(scan_results: SCAN_RESULTS_TYPE, limit: int = DEFAULT_CVE_LIMIT) -> SCAN_RESULTS_TYPE:
    """
    Adds cves to all port data it can.
    :param scan_results: The data provided from full_scan() in models.py.
    :param limit: The max amount of cves added to the port data.
    :return: The scan results with the cves added.
    """
    for interface in list(scan_results):
        for ip_index in range(len(scan_results[interface])):
            for port_data_index in range(len(scan_results[interface][ip_index]["ports_data"])):
                if scan_results[interface][ip_index]["ports_data"][port_data_index].get("cpe") is None:
                    continue
                try:
                    cves = get_cpe_cves(
                        scan_results[interface][ip_index]["ports_data"][port_data_index]["cpe"], limit)
                except socket.error:
                    cves = None
                if cves is not None:
                    scan_results[interface][ip_index]["ports_data"][port_data_index]["cves"] = cves
    return scan_results


def handle_scan(preset_index: int = None, interfaces: list[str] = None, progress_callback=None) -> SCAN_RESULTS_TYPE:
    """
    Uses the information from presets as parameters for the full_scan subroutine of models and adds extra optional
    information about Cpes and Cves.
    :param preset_index: An integer representing the index of the preset in 'presets.json'.
    :param interfaces: A list of interfaces (strings), must match an interface given by the 'ipconfig' command in cmd.
    :param progress_callback: a subroutine that is provided with the parameters (in the order provided):
     interface_scanned_percentage: float, interface_number: int, total_interfaces: int, scan_status: bool. This
     subroutine is called to update the user on the scans progress.
    :return: The scan results of type SCAN_RESULTS_TYPE, a constant.
    :raise ValueError: If preset_index is not in the range of presets.
    """
    if preset_index is None:

        # Uses all interfaces if no default interfaces provided.
        if not interfaces:
            interfaces = get_interfaces()

        # Catch any ParsingErrors of nmap-service-probes.txt
        try:
            scan_results = full_scan(DEFAULT_PORTS, interfaces, progress_callback=progress_callback)
        except ParsingError as error:
            correct_file_error(error)
            return {}
        return add_cve_results(add_cpe_results(scan_results), DEFAULT_CVE_LIMIT)

    if not isinstance(preset_index, int):
        raise TypeError("preset_index must be type int")

    presets = get_presets()
    # presetIndex should be less the number of presets since indexing starts at 0.
    # presetIndex also shouldn't be negative
    if 0 <= preset_index < len(presets):
        preset = presets[preset_index]
        ports = preset["ports"]
        allow_timeout_override = preset["allow_timeout_override"]
        timeout = preset["timeout"]
        get_cpe = preset["get_cpe"]
        cve_limit = preset["cve_limit"]
        delay = preset["delay"]

        # Uses all interfaces if no default interfaces provided
        if not interfaces:
            interfaces = get_interfaces()

        # Catch any ParsingErrors of nmap-service-probes.txt
        try:
            scan_results = full_scan(ports=ports, interfaces=interfaces, timeout=timeout,
                                     allow_timeout_override=allow_timeout_override, delay=delay,
                                     progress_callback=progress_callback)
        except ParsingError as error:
            correct_file_error(error)
            return {}

        if get_cpe:
            if cve_limit:
                return add_cve_results(add_cpe_results(scan_results), cve_limit)
            return add_cpe_results(scan_results)
        return scan_results
    else:
        raise ValueError("preset_index must be in range")


def create_preset(preset_info: dict) -> None:
    """
    Creates a preset from data in preset_info.
    :param preset_info: A dictionary containing all the information of a preset.
    :return: None.
    """
    presets = get_presets()
    presets.append(preset_info)
    write_to_presets(presets)


def delete_preset(preset_index: int) -> None:
    """
    Deletes the preset with the entered preset index from presets.json.
    :param preset_index: index of preset in presets.json.
    :return: None.
    """
    presets = get_presets()
    if 0 <= preset_index < len(presets):
        del presets[preset_index]
        # Write the presets back to the file without the deleted item.
        write_to_presets(presets)


def write_to_presets(presets: list) -> None:
    """
    Rewrites presets.json with the presets entered.
    :param presets: All presets to be written to presets.json
    :return: None.
    """
    try:
        with open("presets.json", "w") as file:
            json.dump(presets, file)
    except (FileNotFoundError, json.decoder.JSONDecodeError) as error:
        if isinstance(error, json.decoder.JSONDecodeError):
            error.doc = "presets.json"
        correct_file_error(error)


def get_presets() -> list:
    """
    Gets the presets from presets.json.
    :return: A list of presets (dictionaries) or an empty list.
    """
    presets = []
    try:
        with open("presets.json", "r") as file:
            presets = json.load(file)
    except (FileNotFoundError, json.decoder.JSONDecodeError) as error:
        if isinstance(error, json.decoder.JSONDecodeError):
            error.doc = "presets.json"
        correct_file_error(error)
    return presets


def get_interfaces() -> list[str]:
    """
    Gets the interfaces from parse_ipconfig().
    :return: A list of interfaces.
    """
    return list(parse_ipconfig())
