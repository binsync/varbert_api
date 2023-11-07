from varmodel.api import VariableRenamingAPI

from yodalib.api import DecompilerInterface

decompiler = DecompilerInterface.discover_interface(force_decompiler="ghidra")
target_function = decompiler.functions[0x40071d]
dec_text = decompiler.decompile(target_function.addr)
api = VariableRenamingAPI(decompiler_name="ghidra")
api.predict_and_apply_variable_names(target_function, decompilation_text=dec_text, use_decompiler=True)