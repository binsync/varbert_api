import logging
from typing import Optional, Dict, Tuple

from .text_processor import DecompilationTextProcessor
from .model import VARModelInterface

from yodalib.data import Function
from yodalib.api import DecompilerInterface

_l = logging.getLogger(__name__)


class VariableRenamingAPI:
    def __init__(
        self,
        decompiler_interface=None,
        decompiler_name=None,
        use_decompiler=True,
        delay_init=False,
        min_func_size=0x10
    ):
        self._dec_interface = DecompilerInterface.discover_interface(force_decompiler=decompiler_name) \
            if use_decompiler and decompiler_interface is None else decompiler_interface
        self._dec_name = decompiler_name if decompiler_interface is None else decompiler_interface.name
        self._model_interface: Optional[VARModelInterface] = (
            VARModelInterface(decompiler=self._dec_name)
        ) if not delay_init else None

        if self._dec_interface is None and not self._dec_name:
            raise ValueError("You must either provide a decompiler name or a decompiler interface.")

        self._min_func_size = min_func_size

    def predict_variable_names(
        self, function: Function = None, decompilation_text: Optional[str] = None, use_decompiler=True,
        remove_bad_names=True
    ) -> Tuple[Dict[str, str], str]:
        """
        Predict variable names for a function or decompilation text. You can use this function in two ways:
        1. Provide a Function object and use_decompiler (most accurate)
        2. Provide decompilation text and not use_decompiler (less accurate)

        Note: you must have the models installed for the decompiler_name you are using.

        Example use without decompiler:
        >>> from varmodel import VariableRenamingAPI
        >>> api = VariableRenamingAPI(decompiler_name="ida", use_decompiler=False)
        >>> new_names, new_code = api.predict_variable_names(decompilation_text="__int64 sub_400664(char *a1,char *a2)\n {}", use_decompiler=False)


        :param function:            Function object to predict names for, should have stack variables and arguments
        :param decompilation_text:  Decompilation text to predict names for
        :param use_decompiler:      Enables using the connected Decompiler API to get accurate variable names
        :param remove_bad_names:    Removes names that are duplicates or decompiler generated
        :return: (dict of old name to new name, renamed code)
        """
        # sanity checks
        if function is None and decompilation_text is None:
            raise ValueError("Must provide either a Function or decompilation text.")
        if function:
            if not function.args and not function.stack_vars:
                _l.debug(f"{function} has no arguments or stack variables to predict names for.")
                return {}, ""
            if function.size < self._min_func_size:
                _l.debug(f"{function} is smaller than min size of {self._min_func_size} bytes.")
                return {}, ""
        # can be None because of the delay init
        if self._model_interface is None:
            self._model_interface = VARModelInterface(decompiler=self._dec_name)

        if decompilation_text is None:
            if not use_decompiler:
                raise ValueError("Must provide decompilation text if not using decompiler")

            decompilation_text = self._dec_interface.decompile(function.addr)

        # preprocess text for training
        preprocessor = DecompilationTextProcessor(
            decompilation_text, func=function, decompiler=self._dec_interface if use_decompiler else None
        )
        processed_code, func_args = preprocessor.processed_code, preprocessor.func_args
        scores, score_origins = self._model_interface.process(processed_code)
        if scores is None:
            scores = "Unparsable code or input exceeding maximum length"

        orig_name_2_popular_name, renamed_code = preprocessor.generate_popular_names(
            processed_code, func_args, scores, score_origins,
            predict_for_decompiler_generated_vars=False
        )
        if not orig_name_2_popular_name:
            _l.warning(f"Unable to predict any names for function {function}")

        if remove_bad_names:
            name_pairs = list()
            new_names = set()
            # remove names that are duplicates
            for orig_name, popular_name in orig_name_2_popular_name.items():
                if popular_name not in new_names:
                    name_pairs.append((orig_name, popular_name))
                    new_names.add(popular_name)

            # remove decompiler based names
            orig_name_2_popular_name = {
                k: v for k, v in name_pairs if "/*decompiler*/" not in v
            }

        # check after filtering
        if orig_name_2_popular_name:
            _l.info(f"Predicted {len(orig_name_2_popular_name)} names for function {function}")

        return orig_name_2_popular_name, renamed_code
