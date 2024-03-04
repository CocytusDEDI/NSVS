from typing import Callable
import re
import socket
import subprocess
import ipaddress
import pcre2
import nvdlib
import time
import tomli

__all__ = ["full_scan", "parse_ipconfig", "ParsingError", "info_to_cpe", "get_cpe_cves", "SCAN_RESULTS_TYPE",
           "DEFAULT_CVE_LIMIT", "DEFAULT_CPE_LIMIT", "CONFIG_PATH"]

# Paths for needed files.
NMAP_SERVICE_PROBES_PATH = "./nmap-service-probes.txt"
CONFIG_PATH = "./config.toml"


class ParsingError(Exception):
    """Raise if file could not be interpreted."""

    def __init__(self, filepath) -> None:
        self.filepath = filepath
        super().__init__(f"Failed to interpret {self.filepath}")


# Opens the config file and grabs the contents.
try:
    with open(CONFIG_PATH, "rb") as config_file:
        config = tomli.load(config_file)
except (tomli.TOMLDecodeError, FileNotFoundError):
    config = {}

# Set the default values using config file, if config file doesn't exist then use default values typed into the program.
DEFAULT_PROBE_TIMEOUT = config["models"]["DEFAULT_PROBE_TIMEOUT"] \
    if (config.get("models", {}).get("DEFAULT_PROBE_TIMEOUT")) else 3
DEFAULT_ALLOW_TIMEOUT_OVERRIDE = config["models"]["DEFAULT_ALLOW_TIMEOUT_OVERRIDE"] \
    if (config.get("models", {}).get("DEFAULT_ALLOW_TIMEOUT_OVERRIDE")) else True
DEFAULT_CPE_LIMIT = config["models"]["DEFAULT_CPE_LIMIT"] \
    if (config.get("models", {}).get("DEFAULT_CPE_LIMIT")) else 50
DEFAULT_CVE_LIMIT = config["models"]["DEFAULT_CVE_LIMIT"] \
    if (config.get("models", {}).get("DEFAULT_CVE_LIMIT")) else 3

CVES_TYPE = list[dict]
CPE_TYPE = dict
PORT_DATA_TYPE = dict[str, 'str|int|Exception|None|CPE_TYPE|CVES_TYPE']
DEVICE_DATA_TYPE = dict[str, 'str|list[PORT_DATA_TYPE]']  # list[PORT_DATA_TYPE] is also referred to as ports_data_type
SCAN_RESULTS_TYPE = dict[str, list[DEVICE_DATA_TYPE]]
"""
SCAN_RESULTS_TYPE includes data types that will never exist as output of the function full_scan from models. These 
datatypes are designed to be added in the program that calls full_scan. For this reason, as an example, even though
choose_and_send_probes() returns port data, the PORT_DATA_TYPE datatype contains the possibilities of 
CVES_TYPE and CPE_TYPE which will never be outputs of choose_and_send_probes() and thus the custom datatype 
PORT_DATA_TYPE cannot replace the manually typed smaller version of it.
"""


class File:
    """Used to stop the same file from being reread from unnecessarily by temporarily storing the contents."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self._contents = None

    def get_contents(self) -> list[str]:
        """
        Getter for self._contents.
        :return: The file's contents as a list of strings.
        """
        if self._contents is None:
            with open(self.filename, "r") as file:
                self._contents = file.readlines()
        return self._contents

    def unload_contents(self) -> None:
        """Removes the contents of file from memory."""
        self._contents = None


nmap_service_probes = File(NMAP_SERVICE_PROBES_PATH)


def get_network_and_host_ips(subnet_mask: str, ip_address: str) -> list[str]:
    """
    Uses the ipaddress library to get the host ips.
    :param subnet_mask: A string in the form x.x.x.x where x is an integer and 0<=x<=255 and the previous x is greater
     than or equal to the current x when there is a previous x.
    :param ip_address: A string in the form x.x.x.x where x is an integer. Represents an IPv4 address.
    :return: A list of IPv4 addresses of type string.
    """

    # Split ip address and subnet mask into octets.
    ip_octets = ip_address.split(".")
    subnet_octets = subnet_mask.split(".")

    # Get the network address.
    network_address_octets = []
    for i in range(4):
        network_address_octets.append(int(ip_octets[i]) & int(subnet_octets[i]))
    network_address = ".".join([str(octet) for octet in network_address_octets])

    # Get the list of hosts.
    network = ipaddress.IPv4Network(f"{network_address}/{subnet_mask}", strict=False)
    network_and_host_ip_list = [str(ip) for ip in network.__iter__()]
    # If list is empty, don't delete last element since it doesn't exist.
    if network_and_host_ip_list:
        del network_and_host_ip_list[-1]
    return network_and_host_ip_list


def probe_device(ip: str, port: int, protocol: str, probe_text: bytes = None,
                 timeout: 'float|int' = DEFAULT_PROBE_TIMEOUT) -> str:
    """
    Probes a device using socket to try and retrieve a banner from it.
    :param ip: A string that can be a IPv4 address and various other forms.
    :param port: A positive integer representing a port.
    :param protocol: Must be "TCP" or "UDP".
    :param probe_text: Text to send to target machine to probe a response out.
    :param timeout: How the program should wait for a response back before giving up in seconds.
    :raise socket.error: If connection error occurs.
    :raise UnicodeDecodeError: If error in decoding received banner.
    :return: A banner (the initial response back from a device upon connecting).
    """
    NUMBER_OF_BYTES_TO_RECEIVE = 1024
    # Deciding to use TCP or UDP.
    if protocol == "TCP":
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif protocol == "UDP":
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        raise ValueError("Protocol must be either 'TCP' or 'UDP'")
    connection.settimeout(timeout)
    connection.connect((ip, port))
    # If there is a probe_text, send it.
    if probe_text:
        connection.sendall(probe_text)
    # Receive and decode received data.
    banner = connection.recv(NUMBER_OF_BYTES_TO_RECEIVE).decode().strip("\n").strip("\r")
    connection.close()
    return banner


def parse_ipconfig() -> dict[str, dict[str, 'str|list[str]']]:
    """
    Parses the results of the "IpConfig" cmd command into a dictionary.
    :return: {interface name (string): {property name (string): property value (string), ...}, ...}.
    """
    # Gets the output of the command 'ipconfig' using 'subprocess'.
    # Removes the first 32 characters of output since they don't contain any useful information.
    ipconfig = subprocess.check_output("ipconfig")[32:]
    space_count = 0
    property_part = 0
    in_interface = True
    exited_interface = False
    in_property = False
    property_first_part_dotted = False
    property_started = False
    interface = ""
    prop = ""
    text = ""
    parsed_output = {}

    for char in ipconfig:
        char = chr(char)

        # Collecting interface name.
        if in_interface:
            # If the character is a colon that is the end of the interface.
            if char == ":":
                in_interface = False
                exited_interface = True
                # Create interface.
                parsed_output[interface] = {}
            elif char != "\n":
                # Adding character to interface name.
                interface = interface + char

        # Collecting property.
        elif in_property:
            exited_interface = False
            # Incase property has more than one value.
            if char == " " and property_started is True:
                property_part += 1
                parsed_output[interface][prop] = [parsed_output[interface][prop]]
                text = ""
            elif property_started is True:
                prop = ""
                text = ""
                property_part = 0
            property_started = False
            # Changes to second part if colon appears.
            if char == ":" and property_part == 0:
                property_part = 1
                property_first_part_dotted = False
                # removes blank space
            # Starts ignoring first part of property if dot appears to avoid names including full stops.
            elif property_part == 0 and char == ".":
                property_first_part_dotted = True
                prop = prop.strip()
                parsed_output[interface][prop] = ""
            # Adds character to property.
            elif property_first_part_dotted is False and property_part == 0:
                prop = prop + char
            elif char != "\r" and property_part > 0:
                text = text + char
            elif char == "\r" and property_part > 0:
                in_property = False
                # Removes blank space.
                text = text.strip()
                # If property has more than one value append value, if not assign value.
                if isinstance(parsed_output[interface][prop], list):
                    parsed_output[interface][prop].append(text)
                else:
                    parsed_output[interface][prop] = text

        # If there are three spaces in a row it's a property.
        elif char == " ":
            space_count += 1
            if space_count == 3:
                # Start collecting property.
                in_property = True
                property_started = True
                space_count = 0

        # Starting interface if not just exited interface.
        elif char == "\r" and not exited_interface:
            interface = ""
            in_interface = True

    return parsed_output


def get_nmap_probes(ports: list[int]) -> list[list[dict[str, 'str|int|float|list[int]|list[dict[str, str|int]]']]]:
    """
    Parses nmap-service-probes for probes matching the ports being searched for.
    :param ports: A list of ports which are positive integers.
    :return: A list containing ten lists, each list contains dictionaries of probes of rarity matching the index
     of the list except for the first list whose probes have no rarity. Each dictionary contains the keys "protocol"
     (string), "probe_name" (string), "probe string" (string), "rarity" (integer), "ports" (list of ints), "matches"
     (list of dictionaries), "total_wait" (float).
    """
    # Create a list of ten empty lists. Read return value docstring description for more help.
    probes = [[] for i in range(10)]
    probe = {}
    # Try statement is used because nmap-service-probes.txt could be corrupt, if so, ParsingError is raised.
    try:
        for line in nmap_service_probes.get_contents():
            # Use string splicing to add probe properties to a dictionary.
            if line[0:5] == "Probe":
                # The probe is parsed with this line, the string trims off the "Probe " part, it then removes.
                # Remove " no-payload" and the "\n", the string is then split at the first two spaces into a list.
                full_probe = line[6:].removesuffix(" no-payload").removesuffix("\n").split(" ", 2)
                probe = {
                    "protocol": full_probe[0],
                    "probe_name": full_probe[1],
                    # The [2:-1] removes the "m" and two delimiters at the start and end.
                    "probe_string": full_probe[2][2:-1],
                    "rarity": 0,
                    "ports": [],
                    "matches": [],
                    "total_wait": 0.0
                }
            elif line[0:6] == "rarity":
                # Rarity ranges from 1 to 9 and thus is always a single character in position 7 of a line.
                probe["rarity"] = int(line[7])
            elif line[0:5] == "ports":
                # Turns the ports string into a list of integers by slicing the string, then turning it into a list
                # of strings, then striping those strings of blank spaces and turning it into an integer.
                for port in line[6:].split(","):
                    if "-" in port:
                        multiports = port.split("-")
                        for new_port in range(int(multiports[0]), int(multiports[1]) + 1):
                            probe["ports"].append(int(new_port))
                    else:
                        probe["ports"].append(int(port.strip()))
            elif line[0:5] == "match":
                probe["matches"].append(get_match_info(line))
            elif line[0:11] == "totalwaitms":
                # Converts from ms to s.
                probe["total_wait"] = int(line[12:]) / 1000
            elif line == "##############################NEXT PROBE##############################\n":
                # If the probe isn't empty and any of the inputted ports are in the probe's list of ports or if no ports
                # where entered, then add probe to the probe list corresponding to its rarity.
                if probe != {} and (any(port in probe["ports"] for port in ports) or probe["ports"] == []):
                    probes[probe["rarity"]].append(probe)
        return probes
    # Turns ValueError and IndexError into custom error: ParsingError
    except (ValueError, IndexError):
        raise ParsingError("nmap-service-probes.txt")


def get_match_info(line: str) -> dict[str, 'str|int']:
    """
    Parses a match from nmap-service-probes into a dictionary.
    :param line: a line of match text from nmap-service-probes.
    :return: "service": service name (string), "pattern": regex pattern (string), "flags": pcre2 flags (int),
     "vendor_product_name": product name (string), "version": version (string), "operating_system": os (string),
     "device_type": device type (string).
    """
    split_match = line[6:].rstrip("\n").split(" ", 1)
    pattern_match = re.match(r'm(?P<delimiter>.)(?P<pattern>.*?)\1(?P<flags>[is]*)', split_match[1], flags=re.DOTALL)
    vendor_product_name = re.search(r'p/(.*?)/', split_match[1])
    version = re.search(r'v/(.*?)/', split_match[1])
    operating_system = re.search(r'o/(.*?)/', split_match[1])
    device_type = re.search(r'd/(.*?)/', split_match[1])

    pattern = pattern_match.group('pattern') if pattern_match else None
    flags = pattern_match.group('flags') if pattern_match else ''

    # Performing binary 'or' on pattern_flags. This puts the flags into a single usable value.
    pattern_flags = 0
    if 'i' in flags:
        pattern_flags |= pcre2.I
    if 's' in flags:
        pattern_flags |= pcre2.S

    return {
        "service": split_match[0],
        "pattern": pattern,
        "flags": pattern_flags,
        "vendor_product_name": vendor_product_name.group(1) if vendor_product_name else None,
        "version": version.group(1) if version else None,
        "operating_system": operating_system.group(1) if operating_system else None,
        "device_type": device_type.group(1) if device_type else None
    }


# Ignore the next comment, it's used for PyCharm.
# noinspection PyUnresolvedReferences
def match_response(response: str, matches: list[dict]) -> dict[str, 'str|int']:
    """
    Uses regex to see if the response/banner matches the nmap-service-probes match.
    :param response: The response/banner back from a device.
    :param matches: A list of dictionaries that contain the "pattern" and "flags" key.
    :return: A match dictionary or an empty dictionary.
    """
    for match in matches:
        if match.get("pattern") is not None:
            # Unfortunately pcre2 does not perfectly compile all the nmap service probe matches so this is just a
            # heuristic method.
            try:
                pattern = pcre2.compile(match["pattern"], match["flags"])
            except pcre2.exceptions.CompileError:
                continue
            # Pcre2 is weird since instead of returning none when no matches are found,
            # it throws an error which needs to be caught.
            try:
                if pattern.match(response):
                    return match
            except pcre2.exceptions.MatchError:
                pass
    return {}


def info_to_cpe(vendor_product_name: str, version: str = None, limit: int = DEFAULT_CPE_LIMIT) -> 'None|CPE_TYPE':
    """
    Uses nvdlib to get cpes from the vendor_product_name and uses the version to ensure they match.
    :param version: optional: version of the cpe to search for.
    :param vendor_product_name: cpe to search for.
    :param limit: A limit for the number of cpes to get.
    :return: Either None or a CPE dictionary.
    """
    # Converts the list of cpe objects into a list of dictionaries.
    cpes = list(map(lambda cpe: cpe.__dict__, nvdlib.searchCPE(keywordSearch=vendor_product_name, limit=limit)))
    # If no results come back, return None.
    if not cpes:
        return None
    if version is None:
        return cpes[0]
    # Search through returned cpes to check for a matching version.
    for cpe in cpes:
        # The number 5 used is the position in the list where version number always is.
        cpe_version = cpe.cpeName.split(":")[5]
        if cpe_version != "-":
            if is_same_version(version.removeprefix("$"), cpe_version):
                return cpe
    # If no Cpe matches, return None.
    return None


def get_cpe_cves(cpe: str, limit: int = DEFAULT_CVE_LIMIT) -> 'None|CVES_TYPE':
    """
    Uses nvdlib to get cves from a cpe.
    :param cpe: Common platform enumeration string.
    :param limit: The number of cves to get.
    :return: A list of cves or None.
    """
    # Converts the list cve objects into a list of dictionaries.
    cves = list(map(lambda cve: cve.__dict__, nvdlib.searchCVE(cpeName=cpe, limit=limit)))
    if cves:
        return cves
    return None


def is_same_version(version_one: str, version_two: str) -> bool:
    """
    Compares two semantic versions to see if they're the same.
    :param version_one: A semantic version.
    :param version_two: A semantic version.
    :return: True or False.
    """
    # Turns a version into a list of numbers. All empty strings in the list of numbers made by split() are turned into
    # "0" by using an or statement.
    version_one = [version_part.strip() or "0" for version_part in version_one.split(".")]
    version_two = [version_part.strip() or "0" for version_part in version_two.split(".")]

    print(version_one)
    print(version_two)

    # Find the longer and smaller version numbers.
    if len(version_two) >= len(version_one):
        larger_version = version_two
        smaller_version = version_one
    else:
        larger_version = version_one
        smaller_version = version_two

    # Iterate through the versions and check each part is equal to each other.
    for i in range(len(larger_version)):
        if i < len(smaller_version):
            if int(version_two[i]) != int(version_one[i]):
                return False
        elif int(larger_version[i]) != 0:
            return False
    return True


def choose_and_send_probe(ip: str, port: int, timeout: 'int|float' = DEFAULT_PROBE_TIMEOUT,
                          allow_timeout_override: bool = DEFAULT_ALLOW_TIMEOUT_OVERRIDE) -> \
        dict[str, 'str|int|Exception']:
    """
    A probe is chosen based on the port inputted and then sent.
    :param ip: Device's ip address.
    :param port: Intended port to send to.
    :param timeout: How long to wait for a response in seconds.
    :param allow_timeout_override: If the nmap-service-probes database can use its own timeout times
     (may make the program slower if enabled).
    :return: {"protocol": "TCP"|"UDP" (string), "probe_name": name of probe (string), "banner": banner (string),
     "service": service name (string), "vendor_product_name": name of product (string), "version": version (string),
     "operating_system": os (string), "device_type": device type (string), "port": port (int),
     "connection_status": Represents if the connection was successful or not (True|Exception)}
    """
    # Get probe and parameters for probe_device.
    probe = choose_probe(port)
    if allow_timeout_override and probe["total_wait"] != 0:
        timeout = probe["total_wait"]
    if probe["rarity"] == 0:
        probe_text = None
    else:
        probe_text = bytes(probe["probe_string"], "utf-8")

    # Attempt probe of device.
    try:
        banner = probe_device(ip, port, probe["protocol"], probe_text, timeout)
    except (socket.error, UnicodeDecodeError) as error:
        banner = error


    # Returns relevant information based on probe outcome.
    if isinstance(banner, Exception):
        return {"protocol": probe["protocol"], "port": port, "connection_status": banner}
    else:
        port_data = match_response(banner, probe["matches"])
        # If port_data isn't empty, delete useless data.
        if port_data:
            # Remove pattern and flags from the dictionary since they're now useless.
            del port_data["pattern"]
            del port_data["flags"]
        # Add the banner, protocol and probe name to the device info dictionary.
        port_data.update({"protocol": probe["protocol"], "probe_name": probe["probe_name"], "banner": banner,
                          "port": port, "connection_status": True})
        return port_data


def choose_probe(port: int) -> dict[str, 'str|int|float|list[int]|list[dict[str, str|int]]']:
    """
    Chooses the best probe for inputted port.
    :param port: A positive integer representing the port the probe will be sent to.
    :return: A probe dictionary.
    """
    # Get all probes that can be sent on the given port.
    probes = get_nmap_probes([port])
    # Iterate through rarities, from most likely to work to least likely to work until probe found.
    for probe_list_number in range(9):
        probe_list_number += 1
        if probes[probe_list_number]:
            return probes[probe_list_number][0]
    # If none found return default probe.
    return probes[0][0]


def full_scan(ports: list[int], interfaces: list[str], timeout: float = DEFAULT_PROBE_TIMEOUT,
              allow_timeout_override: bool = DEFAULT_ALLOW_TIMEOUT_OVERRIDE, delay: float = 0,
              progress_callback: Callable = None) -> SCAN_RESULTS_TYPE:
    """
    Scans through every device on the subnet that the device running the program is on and returns info on each device.
    :param ports: A list of ports, all ports should be integers.
    :param interfaces: A list of interfaces, all interfaces should be strings.
    :param allow_timeout_override: A boolean determine if nmap service probes can override the timeout value.
    :param delay: A float that artificially adds delay between each device scanned to avoid excessive network traffic.
    :param timeout: A float determining how long the program waits for a reply back from a device.
    :param progress_callback: a subroutine that is provided with the parameters (in the order provided):
     interface_scanned_percentage: float, interface_number: int, total_interfaces: int, scan_status: bool. This
     subroutine is called to update the user on the scans progress.
    :return: {interface (string): [{"ip": ip (string), "ports_data": []}, ...], ...} where ports_data can be empty or
     contain dictionaries of string keys and (integer, string or exception) values.
    """
    interface_data = {}
    interface_number = 1
    total_interfaces = len(interfaces)
    parsed_ipconfig = parse_ipconfig()
    # Loop through network interfaces to find the subnet mask.
    for interface in interfaces:
        subnet_mask = None
        ip_address = None
        for ipconfig_interface in list(parsed_ipconfig):
            if ipconfig_interface == interface:
                for key in list(parsed_ipconfig[ipconfig_interface]):
                    if "ipv4 address" in key.lower():
                        ip_address = parsed_ipconfig[ipconfig_interface][key]
                    elif "subnet mask" in key.lower():
                        subnet_mask = parsed_ipconfig[ipconfig_interface][key]

        subnet_data = []
        if subnet_mask is not None and ip_address is not None:
            # Get ips and then scan each one.
            ip_list = get_network_and_host_ips(subnet_mask, ip_address)
            ip_number = 0
            ip_list_len = len(ip_list)
            for ip in ip_list:
                if progress_callback:
                    # Multiplying by 100 to turn (ip_number / ip_list_len) into a percentage.
                    progress_callback((ip_number / ip_list_len) * 100, interface_number, total_interfaces, False)
                    ip_number += 1
                # Go through all the ports being scanned.
                ip_data = {"ip": ip, "ports_data": []}
                for port in ports:
                    port_data = choose_and_send_probe(ip, port, timeout, allow_timeout_override)
                    time.sleep(delay)
                    if port_data:
                        ip_data["ports_data"].append(port_data)
                subnet_data.append(ip_data)
            if progress_callback:
                # 100 because scan 100% complete, false because scan didn't fail.
                progress_callback(100, interface_number, total_interfaces, False)
        elif progress_callback:
            # 100 because scan 100% complete, true because scan did fail.
            progress_callback(100, interface_number, total_interfaces, True)
        interface_data[interface] = subnet_data
        interface_number += 1
    # Unload contents incase on next scan contents have changed and to free RAM.
    nmap_service_probes.unload_contents()
    return interface_data
