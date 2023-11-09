import argparse
import logging
import sys

from yodalib.decompilers import YODALIB_SUPPORTED_DECOMPILERS, GHIDRA_DECOMPILER


import varmodel
from varmodel import SUPPORTED_MODELS, VariableRenamingAPI, install_model, predict_for_functions
from varmodel.installer import VarmodelPluginInstaller


_l = logging.getLogger(__name__)


class Commands:
    DOWNLOAD_MODELS = "download-models"
    INSTALL = "install"
    PREDICT = "predict"
    ALL_COMMANDS = [DOWNLOAD_MODELS, PREDICT, INSTALL]


def install(decompiler):
    VarmodelPluginInstaller().install()


def main():
    parser = argparse.ArgumentParser(description="""
    The Variable Renaming Model is a model that predicts variable names based on the decompiled code.
    This script is used either inside a decompiler or to spawn a decompiler. 
    """)
    parser.add_argument("cmd", type=str, choices=Commands.ALL_COMMANDS, help="Command to run")
    parser.add_argument("--decompiler", type=str, choices=YODALIB_SUPPORTED_DECOMPILERS, help="Decompiler to use")
    parser.add_argument("--functions", type=str, nargs="+", help="Functions to predict on")
    parser.add_argument("--reinstall", action="store_true", default=False, help="Re-download and reinstall the models")
    parser.add_argument("-v", "--version", action="version", version=f"VARModel {varmodel.__version__}")
    args = parser.parse_args()

    if args.cmd == Commands.DOWNLOAD_MODELS:
        for target in SUPPORTED_MODELS:
            install_model(target, opt_level="O0", reinstall=args.reinstall)
    elif args.cmd == Commands.INSTALL:
        install(args.decompiler)
    elif args.cmd == Commands.PREDICT:
        functions = args.functions
        if functions:
            functions = [int(func, 0) for func in args.functions]
            predict_for_functions(func_addrs=functions, decompiler=args.decompiler)
        else:
            function_text = sys.stdin.read()
            api = VariableRenamingAPI(decompiler_name=args.decompiler, use_decompiler=False)
            new_names, new_code = api.predict_variable_names(decompilation_text=function_text, use_decompiler=False)
            print(new_code)


if __name__ == "__main__":
    main()
