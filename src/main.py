from api import handle_scan, create_preset, delete_preset, get_interfaces, get_presets, NUMBERS
import sys


def main_menu() -> None:
    """
    Start point of the program, gives the user the choice of the default scan, preset scan and to manage the presets.
    :return: None
    """
    print("Please keep in mind 'exit' or 'quit' can be typed to leave a menu at any time")
    while True:
        scan_choice = input("Options:\n1. Default scan\n2. Preset scan\n3. Manage presets\n>").lower().strip()
        if scan_choice == "default scan" or scan_choice == "1":
            interfaces = choose_interfaces()
            print()
            results_menu(handle_scan(interfaces=interfaces, progress_callback=progress_callback))
        elif scan_choice == "preset scan" or scan_choice == "2":
            print()
            preset_scan()
        elif scan_choice == "manage presets" or scan_choice == "3":
            print()
            manage_presets_menu()
        elif scan_choice == "exit" or scan_choice == "quit":
            break
        else:
            print("Please enter valid option\n")


def progress_callback(interface_scanned_percent, interface_number, total_interfaces, failed: bool) -> None:
    """
    Called to inform the user of the scans progress. Should only be passed to handle_scan() and not explicitly called in
    main.py.
    :param interface_scanned_percent: Percentage of the current interface scanned.
    :param interface_number: The number of the current interface being scanned.
    :param total_interfaces: The total number of interfaces being scanned.
    :param failed: If the program failed to scan the current interface or not.
    :return: None
    """
    if failed:
        print("Scan failed: interface {} of {}".format(interface_number, total_interfaces))
    else:
        sys.stdout.write("\rScanning progress: {:.1f}%, interface {} of {}"
                         .format(interface_scanned_percent, interface_number, total_interfaces))
        sys.stdout.flush()
        if interface_scanned_percent == 100:
            print()


def choose_interfaces() -> list[str]:
    """
    Gives the user a choice of interfaces.
    :return: A list of interfaces.
    """
    # return: list of strings
    chosen_interfaces = []

    # get data on network chosen_interfaces
    interfaces = get_interfaces()

    print("Please enter all of the interface numbers separated by commas you would like to scan, e.g. 1, 2, 5. If none "
          "are entered, all will be scanned.")

    # print out user chosen_interfaces
    for i in range(len(interfaces)):
        print(str(i + 1) + ". " + interfaces[i])

    # get user choice and interpret it
    interface_choice = input(">")
    chosen = interface_choice.split(",")
    for chosen_num in chosen:
        chosen_num = chosen_num.strip()
        if chosen_num in NUMBERS:
            # converts the input into index
            chosen_num = int(chosen_num) - 1
            # add user choice to a list
            chosen_interfaces.append(interfaces[chosen_num])
    return chosen_interfaces


def attempt_create_preset() -> None:
    """
    Prompts the user for input to create a preset.
    :return: None
    :raise ValueError: Raises if invalid values are entered. First argument is the error message and the second is the
     invalid input.
    """
    name = input("Name: ").strip()
    ports = input("Ports (separated by commas): ").strip().split(",")
    if not all([port.strip().isdigit() for port in ports]) or name.lower() == "exit" or name.lower() == "quit":
        raise ValueError("Invalid ports: not all digits.", ports[0])
    ports = [int(port) for port in ports]

    timeout = input("Connection timeout time (seconds): ").strip().lower()
    if not timeout.replace(".", "", 1).isdigit():
        raise ValueError("Invalid timeout: not digit.", timeout)
    timeout = float(timeout)

    allow_timeout_override = input("Allow timeout override (true/false): ").strip().lower()
    if allow_timeout_override == "false":
        allow_timeout_override = False
    elif allow_timeout_override == "true":
        allow_timeout_override = True
    else:
        raise ValueError("Invalid allow timeout override: not boolean (true/false).", allow_timeout_override)

    get_cpe = input("Get CPE (true/false): ").strip().lower()
    if get_cpe == "false":
        get_cpe = False
    elif get_cpe == "true":
        get_cpe = True
    else:
        raise ValueError("Invalid get CPE: not boolean (true/false).", get_cpe)

    if get_cpe:
        cve_limit = input("Cve (vulnerabilities) limit per cpe (positive integer): ").strip()
        if not cve_limit.isdigit():
            raise ValueError("Invalid cves limit: not a digit.", cve_limit)
        cve_limit = int(cve_limit)
    else:
        cve_limit = 0

    delay = input("Delay between scans (seconds): ").strip().lower()
    if not delay.replace(".", "", 1).isdigit():
        raise ValueError("Invalid delay: not digit.", delay)
    delay = float(delay)

    create_preset({"name": name, "ports": ports, "timeout": timeout, "allow_timeout_override": allow_timeout_override,
                   "get_cpe": get_cpe, "delay": delay, "cve_limit": cve_limit})


def manage_presets_menu() -> None:
    """
    A menu with the options of creating, deleting and displaying presets.
    :return: None
    """

    custom_choice = input("Options:\n1. Create\n2. Delete\n3. Display\n>").lower().strip()
    print()

    if custom_choice == "create" or custom_choice == "1":
        while True:
            try:
                attempt_create_preset()
            except ValueError as error:
                # Errors manually raised by attempt_create_preset() have two args, the first is the error message, the
                # second is the invalid input which could be "exit" or "quit".
                if len(error.args) != 2:  # This check must be here to stop the elif from throwing an IndexError.
                    print(error.args[0])
                elif error.args[1].lower().strip() == "exit" or error.args[1].lower().strip() == "quit":
                    print()
                    break
                else:
                    print(error.args[0])
                continue  # Retry attempt_create_preset()

            print("\nPreset created\n")
            break

    elif custom_choice == "delete" or custom_choice == "2":
        print_presets()
        while True:
            preset_num = input("Enter the preset number to delete: ").strip().lower()
            if preset_num.isdigit():
                preset_num = int(preset_num) - 1
                if preset_num <= len(get_presets()):
                    delete_preset(preset_num)
                    print("\nPreset deleted\n")
                    break
                else:
                    print("not a valid preset number")
            elif preset_num == "exit" or preset_num == "quit":
                break
            else:
                print("enter a number")

    elif custom_choice == "display" or custom_choice == "3":
        if len(get_presets()) == 0:
            print("No presets\n")
        else:
            print_presets()


def print_presets() -> None:
    i = 1
    for preset in get_presets():
        ports = str(preset["ports"]).removeprefix("[").removesuffix("]")
        print(str(i) + ".")
        print("Name: " + preset["name"])
        print("Ports: " + ports)
        print("Timeout: " + str(preset["timeout"]))
        print("Allow timeout override: " + str(preset["allow_timeout_override"]))
        print("Get CPE: " + str(preset["get_cpe"]))
        print("CVE limit: " + str(preset["cve_limit"]))
        print("Delay: " + str(preset["delay"]))
        print()
        i += 1


def preset_scan() -> None:
    num_of_presets = len(get_presets())
    if num_of_presets == 0:
        print("No presets\n")
        return

    print("Choose preset number:\n")
    print_presets()

    valid_preset = False
    while not valid_preset:
        preset_choice = input(">")
        if preset_choice.isdigit():
            preset_choice = int(preset_choice)
            if 1 <= preset_choice <= num_of_presets:
                print()
                interfaces = choose_interfaces()
                print()
                results_menu(handle_scan(int(preset_choice) - 1, interfaces, progress_callback))
                valid_preset = True
            else:
                print("input a number in range")
        else:
            print("input a number")


def choose_dictionary_value_from_dictionary(dictionary: dict, data_name: str) -> (list[str], dict):
    print("0. Exit")
    i = 1
    for interface in list(dictionary):
        print(str(i) + ". " + data_name + ": " + interface)
        i += 1
    return list(dictionary), dict


def choose_sub_dictionary_from_list_of_dictionaries(list_of_dict: list[dict], data_name: str, key: str) \
        -> (list[dict], list):
    print("0. Back")
    i = 1
    for dictionary in list_of_dict:
        print(str(i) + ". " + data_name + ": " + str(dictionary[key]))
        i += 1
    return list_of_dict, list


def choose_device(list_of_device_dicts: list[dict]) -> (list[dict], list):
    print("0. Back")
    i = 1
    for device in list_of_device_dicts:
        print(str(i) + ". ip: " + str(device["ip"]) + ", successful connections: " +
              str(len([1 for port_data in device["ports_data"] if port_data["connection_status"] is True])))
        i += 1
    return list_of_device_dicts, list


def choose_dictionary_key_value_pair(dictionary: dict) -> (list[str], dict):
    print("0. Back")
    i = 1
    for key in list(dictionary):
        if isinstance(dictionary[key], list):
            print(str(i) + ". " + str(key) + ": [...] (length " + str(len(dictionary[key])) + ")")
        elif isinstance(dictionary[key], dict):
            print(str(i) + ". " + str(key) + ": {...} (length " + str(len(dictionary[key])) + ")")
        else:
            print(str(i) + ". " + str(key) + ": " + str(dictionary[key]))
        i += 1
    return list(dictionary), dict  # ports


def display_dictionary(dictionary: dict) -> (None, None):
    i = 1
    for key in list(dictionary):
        print(str(i) + ". " + str(key) + ": " + str(dictionary[key]))
        i += 1
    return None, None


def get_choice(data) -> 'int|str|None':
    options, data_type = data
    done = False
    if data_type is None:
        input("Enter anything to continue...")
        return None
    while not done:
        choice = input(">").strip().lower()

        if all([character in NUMBERS for character in choice]) and choice != "":
            if 1 <= int(choice) <= len(options):
                if data_type == list:
                    return int(choice) - 1
                return options[int(choice) - 1]
            elif int(choice) == 0:
                return -1
            else:
                print("Please enter a number in the range.")


def results_menu(data) -> None:
    """
    Recursively displays the results of a scan.
    :param data: Could be multiple datatypes, but initial value is most likely of type SCAN_RESULTS_TYPE.
    :return: None.
    """
    while True:
        print()
        if isinstance(data, dict):
            if data.get("port"):  # if data is port data.
                choice = get_choice(choose_dictionary_key_value_pair(data))
                if choice == -1:
                    return
                elif isinstance(data[choice], list):
                    results_menu(data[choice])
                elif isinstance(data[choice], dict):
                    results_menu(data[choice])
                else:
                    input("Empty: Enter anything to continue...")
            elif data.get("id") or data.get("cpeName"):  # if data is cpe or cve.
                display_dictionary(data)
                return
            else:  # data is interfaces.
                choice = get_choice(choose_dictionary_value_from_dictionary(data, "interface"))
                if choice != -1:
                    results_menu(data[choice])
                else:
                    print()
                    return
        elif isinstance(data, list):
            if not data:
                input("Empty: Enter anything to continue...")
                return
            elif data[0].get("port"):  # If data is ports data.
                choice = get_choice(choose_sub_dictionary_from_list_of_dictionaries(data, "port", "port"))
                if choice != -1:
                    results_menu(data[choice])
                else:
                    return
            elif data[0].get("id"):  # If data is cves.
                choice = get_choice(choose_sub_dictionary_from_list_of_dictionaries(data, "cve", "id"))
                if choice != -1:
                    results_menu(data[choice])
                else:
                    return
            else:  # Data is devices (also referred to as ips).
                choice = get_choice(choose_device(data))
                if choice != -1:
                    results_menu(data[choice]["ports_data"])
                else:
                    return


if __name__ == "__main__":
    print("nmap-service-probes.txt is under the copyright of (C) 2003-2006 by Insecure.Com LLC.\nNo warranty is "
          "provided for nmap-service-probes.txt or the rest of the program.\nboth nmap-service-probes.txt and this program "
          "are under the General Public License which can be found at: "
          "https://www.gnu.org/licenses/old-licenses/gpl-1.0.html\n")
    main_menu()
