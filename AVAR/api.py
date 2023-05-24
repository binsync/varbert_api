import logging
import argparse
import torch

from .data_loaders import BSDataLoader
from .model import AVARInterface

logger = logging.getLogger(__name__)


def init_model():
    model_interface = AVARInterface()
    g_model, g_tokenizer, g_device = model_interface.varec_init()
    g_model.to(g_device)
    if torch.cuda.is_available():
        g_model.half()

    return model_interface, g_model, g_tokenizer, g_device

# def binsync_predict(model_interface, model, tokenizer, device, decompilation, Function):
def binsync_predict(model_interface, model, tokenizer, device, decompilation, local_vars, args):
    bsloader = BSDataLoader(
        decompilation,
        local_vars, # Function.stack_vars,
        args # Function.args,
    )

    processed_code, func_args = bsloader.preprocess_binsync_raw_code()
    scores, score_origins = model_interface.process(processed_code, model, tokenizer, device)
    if scores is None:
        scores = "Unparsable code or input exceeding maximum length"
    predicted_code, orig_name_2_popular_name = bsloader.replace_varnames_in_code(processed_code, func_args, scores, score_origins,
                                            predict_for_decompiler_generated_vars=False)
    return orig_name_2_popular_name
