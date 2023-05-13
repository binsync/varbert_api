import re
import os
import json
import logging
from collections import defaultdict
import argparse
import random, string
import pprint 
import torch
import torch.nn as nn
from torch.nn import CrossEntropyLoss

from load_data import BSDataLoader
from varbert_model import varec_init, process

logger = logging.getLogger(__name__)
BASEDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")

BINSYNC_FUNCTIONS = []
BINSYNC_FUNCTIONS_from_file = []
binsync_funcs_path = os.path.join(BASEDIR, "data", "binsync_data.json")
if os.path.isfile(binsync_funcs_path):
    with open(binsync_funcs_path, "r") as f:
        BINSYNC_FUNCTIONS_from_file = json.loads(f.readlines()[0])


MODELS = {
    "ida": "model_ida_O0",
    # "ghidra": "model_ghidra_O0"
}

def predict(args):

    decompiler = args.decompiler
    model_name = MODELS[decompiler]
    print(BASEDIR)
  
    # model initialization
    model_dir = os.path.join(BASEDIR,  "models", MODELS[decompiler])
    if not os.path.isdir(model_dir):
        return {f"Model {decompiler} does not exist on the file system."}
    
    if args.all:
        predict_for_decompiler_generated_vars = True
    else:
        predict_for_decompiler_generated_vars = False


    g_model, g_tokenizer, g_device = varec_init(model_dir)
    g_model.to(g_device)
    if torch.cuda.is_available():
        g_model.half()

    # prepare binsync data for inference
    for funcname, func_data in BINSYNC_FUNCTIONS_from_file.items():
        BINSYNC_FUNCTIONS.append({funcname : BSDataLoader(func_data, decompiler)})

    # prediction
    for func in BINSYNC_FUNCTIONS:
        bsfunc = func
        for funcname, bsloader in bsfunc.items():
            resp = {}
            processed_code, func_args = bsloader.preprocess_binsync_raw_code()
            scores, score_origins = process(processed_code, g_model, g_tokenizer, g_device)
            if scores is None:
                scores = "Unparsable code or input exceeding maximum length"
            predicted_code, orig_name_2_popular_name = bsloader.replace_varnames_in_code(processed_code, func_args, scores, score_origins,
                                                    predict_for_decompiler_generated_vars=predict_for_decompiler_generated_vars)

            # resp['original_to_pred'] = orig_name_2_popular_name

            print(f"original to predicted variables:")
            pprint.pprint(orig_name_2_popular_name)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--decompiler", help="Decompiler name to predict var names")
    parser.add_argument("--all", help="Predict variable names for all variables", action="store_true", default=False)
    args = parser.parse_args()
    predict(args)
