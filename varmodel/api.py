import logging
from typing import Optional, Dict

from .data_loaders import DecompilationTextPreprocessor
from .model import VARModelInterface

from yodalib.data import Function
from yodalib.api import DecompilerInterface

logger = logging.getLogger(__name__)


class VariableRenamingAPI:
    def __init__(self, decompiler=None, decompiler_name="ghidra", use_decompiler=True, delay_init=False):
        self._decompiler = DecompilerInterface.discover_interface(force_decompiler=decompiler_name) \
            if use_decompiler and decompiler is None else decompiler
        self._decompiler_name = decompiler_name if decompiler is None else decompiler.name
        self._model_interface: Optional[VARModelInterface] = (
            VARModelInterface(decompiler=self._decompiler_name)
        ) if not delay_init else None

    def predict_variable_names(
        self, function: Function, decompilation_text: Optional[str] = None, use_decompiler=True
    ) -> Dict[str, str]:
        # can be dropped in init of class
        if self._model_interface is None:
            self._model_interface = VARModelInterface(decompiler=self._decompiler_name)

        # preprocess text for training
        preprocessor = DecompilationTextPreprocessor(
            decompilation_text, func=function, decompiler=self._decompiler if use_decompiler else None
        )
        processed_code, func_args = preprocessor.processed_code, preprocessor.func_args
        scores, score_origins = self._model_interface.process(processed_code)
        if scores is None:
            scores = "Unparsable code or input exceeding maximum length"

        orig_name_2_popular_name = preprocessor.replace_varnames_in_code(
            processed_code, func_args, scores, score_origins,
            predict_for_decompiler_generated_vars=False
        )
        if not orig_name_2_popular_name:
            logger.warning(f"Unable to predict any names for function {function}")

        return orig_name_2_popular_name

    def predict_and_apply_variable_names(
        self, function: Function, decompilation_text: Optional[str] = None, use_decompiler=True
    ):
        orign_name_2_popular_name = self.predict_variable_names(function, decompilation_text=decompilation_text, use_decompiler=use_decompiler)
        orign_name_2_popular_name = {k: v for k, v in orign_name_2_popular_name.items() if "/*decompiler*/" not in v}
        if not orign_name_2_popular_name:
            return False

        return self._decompiler.rename_local_variables_by_names(function, orign_name_2_popular_name)
