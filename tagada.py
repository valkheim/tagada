import os

import idaapi

import tagada

idaapi.require("tagada", package="tagada")


def load(plugin_name: str) -> None:
    package_name = plugin_name.casefold()
    package_path = os.path.join(os.path.dirname(__file__), package_name)
    for entry in os.listdir(package_path):
        if not entry.endswith(".py"):
            continue

        module_name = entry[:-3]
        module_python_path = f"{package_name}.{module_name}"
        idaapi.require(module_python_path)


class Plugin(idaapi.plugin_t):
    NAME = tagada.NAME
    VERSION = "0.0.1"
    AUTHORS = f"The {NAME} team."

    flags = idaapi.PLUGIN_UNL
    comment = f"The {NAME} plugin."
    help = ""
    wanted_name = NAME
    wanted_hotkey = "Alt+f8"

    def print_banner(self) -> None:
        description = f"{Plugin.NAME} v{Plugin.VERSION}"
        copyright = f"(c) {Plugin.AUTHORS}"
        tagada.info("-" * 80)
        tagada.info(f"{description} — {copyright}")
        tagada.info("-" * 80)

    def init(self):
        load(Plugin.NAME)
        tagada.debug("Init")
        try:
            # some initialization routines
            pass

        except Exception as err:
            tagada.error(str(err))
            return idaapi.PLUGIN_SKIP

        self.print_banner()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        tagada.run()
        pass

    def term(self):
        tagada.debug("Term")
        pass


def PLUGIN_ENTRY():
    return Plugin()


if __name__ == "__main__":
    plugin = Plugin()
    plugin.init()
    plugin.run(None)
    plugin.term()
