import argparse
import logging
import sys

import varbert
from varbert import SUPPORTED_MODELS, VariableRenamingAPI, install_model
from libbs.decompilers import IDA_DECOMPILER


_l = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="""
    The Variable Renaming Model is a model that predicts variable names based on the decompiled code.
    This script is used either inside a decompiler or to spawn a decompiler. 
    """)
    parser.add_argument("-d", "--download-models", nargs="*", choices=SUPPORTED_MODELS, help="Download models for supported decompilers. If no decompilers are specified, all models will be downloaded.")
    parser.add_argument("-p", "--predict", action="store_true", help="Predict variable names for a function over stdin and write out the resulting decompilation over stdout")
    parser.add_argument("--decompiler", type=str, choices=SUPPORTED_MODELS, help="Decompiler to use for prediction. If not specified, IDA Pro will be used.", default=IDA_DECOMPILER)
    parser.add_argument("--reinstall", action="store_true", default=False, help="Re-download and reinstall the models")
    parser.add_argument("-v", "--version", action="version", version=f"VarBERT {varbert.__version__}")
    args = parser.parse_args()

    if args.download_models is not None:
        models = args.download_models or SUPPORTED_MODELS
        for model in models:
            install_model(model, reinstall=args.reinstall)
    elif args.predict:
        function_text = sys.stdin.read()
        api = VariableRenamingAPI(decompiler_name=args.decompiler, use_decompiler=False)
        new_names, new_code = api.predict_variable_names(decompilation_text=function_text, use_decompiler=False)
        print(new_code)


if __name__ == "__main__":
    main()
