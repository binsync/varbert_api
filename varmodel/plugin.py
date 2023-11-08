import logging
from typing import Optional, List

from varmodel.api import VariableRenamingAPI

from yodalib.api import DecompilerInterface
from yodalib.ui import progress_bar

_l = logging.getLogger(__name__)
_l.setLevel(logging.INFO)


def predict_for_functions(func_addrs: Optional[List[int]] = None, decompiler: Optional[str] = None):
    dec_interface = DecompilerInterface.discover_interface(force_decompiler=decompiler)
    varbert_api = VariableRenamingAPI(decompiler_interface=dec_interface)
    func_addrs = func_addrs if func_addrs else dec_interface.functions

    # grab real functions, which require decompilation, and predict names for them
    total_suggested_funcs = 0
    total_suggested_vars = 0
    for function_addr in progress_bar(func_addrs, desc="Predicting names...", gui=False):
        # functions can be both non-existent and non-decompilable
        try:
            function = dec_interface.functions[function_addr]
        except Exception:
            continue

        old_to_new_names = varbert_api.predict_variable_names(function)
        if old_to_new_names:
            total_suggested_funcs += 1
            total_suggested_vars += len(old_to_new_names)
            dec_interface.rename_local_variables_by_names(function, old_to_new_names)

    _l.info(f"Suggested names for {total_suggested_vars} variables in {total_suggested_funcs} functions.")
    # make sure things are destroyed
    del varbert_api, dec_interface


if __name__ == "__main__":
    from yodalib.__main__ import main
    main()
