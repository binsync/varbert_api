import logging
import argparse
import torch
from typing import Optional

from .data_loaders import BSDataLoader
from .model import VARModelInterface

from binsync.data import Function

logger = logging.getLogger(__name__)


class VariableRenamingAPI:
    def __init__(self, decompiler="ida"):
        self._decompiler = decompiler
        self._model_interface: Optional[VARModelInterface] = None

    def predict_variable_names(self, function_text: str, function: Function) -> Optional[Function]:
        # init if not done earlier
        if self._model_interface is None:
            self._init_model_interface()

        # places all important names in list format
        #local_vars = [lvar.name for lvar in function.stack_vars.values()] if function.stack_vars else []
        #func_args = [arg.name for arg in function.args.values()] if function.args else []

        # pre-format text for training
        bsloader = BSDataLoader(
            function_text)
        processed_code, func_args = bsloader.preprocess_ida_raw_code()

        scores, score_origins = self._model_interface.process(processed_code)
        if scores is None:
            scores = "Unparsable code or input exceeding maximum length"

        predicted_code, orig_name_2_popular_name = bsloader.replace_varnames_in_code(
            processed_code, func_args, scores, score_origins,
            predict_for_decompiler_generated_vars=False
        )
        if not orig_name_2_popular_name:
            logger.warning(f"Unable to predict any names for function {function}")
            return None

        # apply changes to the function
        new_func: Function = function.copy()
        for orig_name, pop_name in orig_name_2_popular_name.items():
            # skip all variables that are decompiler name predicted
            if "/*decompiler*/" in pop_name:
                continue
            
            for offset, svar in function.stack_vars.items():
                if svar.name == orig_name:
                    new_func.stack_vars[offset].name = pop_name

            for offset, arg in function.args.items():
                if arg.name == orig_name:
                    new_func.args[offset].name = pop_name

        return new_func if new_func != function else None

    def _init_model_interface(self):
        self._model_interface = VARModelInterface(decompiler=self._decompiler)
