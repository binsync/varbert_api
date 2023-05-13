import re
import os
import sys
import json
import logging
from collections import defaultdict
import argparse

import torch
import torch.nn as nn
from torch.nn import CrossEntropyLoss
from transformers import (
    BertConfig,
    BertForMaskedLM,
    BertTokenizer,
    CamembertConfig,
    CamembertForMaskedLM,
    CamembertTokenizer,
    DistilBertConfig,
    DistilBertForMaskedLM,
    DistilBertTokenizer,
    GPT2Config,
    GPT2LMHeadModel,
    GPT2Tokenizer,
    OpenAIGPTConfig,
    OpenAIGPTLMHeadModel,
    OpenAIGPTTokenizer,
    RobertaConfig,
    RobertaForMaskedLM,
    RobertaTokenizer,
)
from transformers.activations import gelu

# from load_data import replace_varnames_in_code, preprocess_binsync_raw_code

logger = logging.getLogger(__name__)
BASEDIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")

MODELS = {
    "ida": "model_ida_O0",
    # "ghidra": "model_ghidra_O0"
}

out_vocab_map = os.path.join(BASEDIR, "models", "model_ida_O0", "idx_to_word.json")
idx_to_word = json.load(open(out_vocab_map))
word_to_idx = dict((v, k) for (k, v) in idx_to_word.items())
vocab_size = len(idx_to_word) + 1
var_size = 2

def change_case(strt):
    return ''.join(['_'+i.lower() if i.isupper()
               else i for i in strt]).lstrip('_')

def is_camel_case(s):
    return s != s.lower() and s != s.upper() and "_" not in s

def  normalize(k):
    if is_camel_case(k):
        k=change_case(k)
    else:
        k=k.lower()
    return k

def get_var_token(norm_variable_word):
    token  = word_to_idx.get(norm_variable_word,vocab_size-1)
    if token == vocab_size-1:
        if "_" in norm_variable_word:
            word_splits=norm_variable_word.split("_")
            for x in word_splits:
                ptoken=word_to_idx.get(x,vocab_size-1)
                if ptoken!=vocab_size-1:
                    token=ptoken
                    break
    return [token]


class RobertaLMHead2(nn.Module):

    def __init__(self,config):
        super().__init__()
        self.dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.layer_norm = nn.LayerNorm(config.hidden_size, eps=config.layer_norm_eps)
        self.decoder = nn.Linear(config.hidden_size, vocab_size, bias=False)
        self.bias = nn.Parameter(torch.zeros(vocab_size))

        # Need a link between the two variables so that the bias is correctly resized with `resize_token_embeddings`
        self.decoder.bias = self.bias

    def forward(self, features, **kwargs):
        x = self.dense(features)
        x = gelu(x)
        x = self.layer_norm(x)

        # project back to size of vocabulary with bias
        x = self.decoder(x)

        return x



class RobertaLMHead3(nn.Module):

    def __init__(self,config):
        super().__init__()
        self.dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.layer_norm = nn.LayerNorm(config.hidden_size, eps=config.layer_norm_eps)
        self.decoder = nn.Linear(config.hidden_size, var_size, bias=False)
        self.bias = nn.Parameter(torch.zeros(var_size))

        # Need a link between the two variables so that the bias is correctly resized with `resize_token_embeddings`
        self.decoder.bias = self.bias

    def forward(self, features, **kwargs):
        x = self.dense(features)
        x = gelu(x)
        x = self.layer_norm(x)

        # project back to size of vocabulary with bias
        x = self.decoder(x)

        return x


class RobertaForMaskedLMv2(RobertaForMaskedLM):


    def __init__(self, config):
        super().__init__(config)
        self.lm_head2 = RobertaLMHead2(config)
        self.lm_head3 = RobertaLMHead3(config)
        self.init_weights()

    def forward(
        self,
        input_ids=None,
        attention_mask=None,
        token_type_ids=None,
        position_ids=None,
        head_mask=None,
        inputs_embeds=None,
        encoder_hidden_states=None,
        encoder_attention_mask=None,
        labels=None,
        output_attentions=None,
        output_hidden_states=None,
        return_dict=None,
    ):
        return_dict = return_dict if return_dict is not None else self.config.use_return_dict

        outputs = self.roberta(
            input_ids,
            attention_mask=attention_mask,
            token_type_ids=token_type_ids,
            position_ids=position_ids,
            head_mask=head_mask,
            inputs_embeds=inputs_embeds,
            encoder_hidden_states=encoder_hidden_states,
            encoder_attention_mask=encoder_attention_mask,
            output_attentions=output_attentions,
            output_hidden_states=output_hidden_states,
            return_dict=return_dict,
        )
        sequence_output = outputs[0]
        prediction_scores = self.lm_head2(sequence_output)
        prediction_scores_vartype = self.lm_head3(sequence_output)
        output_pred_scores = torch.topk(prediction_scores,k=20,dim=-1)
        output_pred_scores_vartype = torch.topk(prediction_scores_vartype, k=1, dim=-1)
        outputs = (output_pred_scores, output_pred_scores_vartype)  # Add hidden states and attention if they are here

        masked_lm_loss = None
        if labels is not None:
            loss_fct = CrossEntropyLoss()
            masked_lm_loss = loss_fct(prediction_scores.view(-1, vocab_size), masked_lm_labels.view(-1))
            outputs = (masked_lm_loss,) + outputs

        return outputs


MODEL_CLASSES = {
    "gpt2": (GPT2Config, GPT2LMHeadModel, GPT2Tokenizer),
    "openai-gpt": (OpenAIGPTConfig, OpenAIGPTLMHeadModel, OpenAIGPTTokenizer),
    "bert": (BertConfig, BertForMaskedLM, BertTokenizer),
    "roberta": (RobertaConfig, RobertaForMaskedLMv2, RobertaTokenizer),
    "distilbert": (DistilBertConfig, DistilBertForMaskedLM, DistilBertTokenizer),
    "camembert": (CamembertConfig, CamembertForMaskedLM, CamembertTokenizer),
}


def varec_init(model_folder="models"):

    if torch.cuda.is_available():
        device = torch.device("cuda")
        logger.info("GPU found, will use GPU for inference.")
    else:
        device = torch.device("cpu")
        logger.warn("GPU not found, inference will be slower.")
    import subprocess
    logger.info("model_folder", model_folder)

    n_gpu = torch.cuda.device_count()
    config_class, model_class, tokenizer_class = MODEL_CLASSES["roberta"]

    config = config_class.from_pretrained(model_folder)
    tokenizer = tokenizer_class.from_pretrained(model_folder)
    model = model_class.from_pretrained(
            model_folder,
            from_tf=False,
            config=config,
        )

    model.to(device)
    return model, tokenizer, device


def create_inputs_for_model(code_txt,tokenizer):
    input_ids = tokenizer.convert_tokens_to_ids(tokenizer.tokenize(code_txt))
    input_ids = tokenizer.build_inputs_with_special_tokens(input_ids)
    return torch.tensor(input_ids, dtype=torch.long)


def split_words(text: str):
    words = text.replace("\n"," ").split(" ")
    r = []
    for w in words:
        m = re.search(r"@@[^\s@]+@@[^\s@]+@@", w)
        if m is not None:
            if m.start() > 0:
                r.append(w[ : m.start()])
            r.append(w[m.start() : m.end()])
            if m.end() < len(w):
                r.append(w[m.end() : ])
        else:
            r.append(w)
    r = [w for w in r if len(w)>0]
    return r


def preprocess_word_mask(ftext, tokenizer):
    words = split_words(ftext)
    pwords =[]
    tpwords =[]
    owords =[]
    towords =[]
    pos=0
    masked_pos=[]
    var_words =[]
    var_toks = []

    vocab=tokenizer.get_vocab()
    for word in words:
        nword=word
        if "@@" in word:
            hasbeg=False
            if word[0]!="@":
                hasbeg=True
            splits = word.split("@@")

            variable_word = splits[-2]
            post_var = splits[-1]

            assert len(variable_word)>0
            norm_variable_word = normalize(variable_word)
            var_tokens = get_var_token(norm_variable_word)
            masked_words = ["<mask>"]*len(var_tokens)
            var_toks.append(var_tokens)
            prefix=""
            if hasbeg:
                prefix=splits[0]
            nword = splits[-2]
            if hasbeg:
                nword=prefix+"@@ " + variable_word

            var_words.append(norm_variable_word)

            if hasbeg:
                pre_toks=tokenizer.tokenize(prefix+"@@")
                for t in pre_toks:
                    pwords.append(t)
                    owords.append(t)
                    tpwords.append(vocab[t])
                    towords.append(vocab[t])
                pos+=1
            for ix,word in enumerate(masked_words):
                pwords.append(word)
                owords.append(var_tokens[ix])
                tpwords.append(vocab[word])
                towords.append(var_tokens[ix])
                masked_pos.append(pos+ix)
            pos+=len(var_tokens)

            if len(post_var)>0:
                pre_toks=tokenizer.tokenize(post_var)
                for t in pre_toks:
                    pwords.append(t)
                    owords.append(t)
                    tpwords.append(vocab[t])
                    towords.append(vocab[t])
                pos+=1

        else:
            toks = tokenizer.tokenize(nword)
            for t in toks:
                pwords.append(t)
                owords.append(t)
                tpwords.append(vocab[t])
                towords.append(vocab[t])
                pos+=1
    assert len(tpwords) == len(towords)
    assert None not in tpwords
    assert None not in towords
    return tpwords, towords, var_words, var_toks


def decode_toks(toks,tokenizer):
    words=[]
    for tok in toks:
        words.append(tokenizer.decode(tok))
    decoded_str = ' '.join(words)
    return decoded_str


def get_inferences(input_ids, tokenizer, model, device):
    input_ids = torch.tensor(input_ids)
    print("Input length of each slice", len(input_ids))
    only_masked = input_ids==tokenizer.mask_token_id
    outputs = model(input_ids.to(device).unsqueeze(0))
    varname_out = outputs[0]
    vartype_out = outputs[1]
    inference = varname_out.indices.cpu()
    values = varname_out.values.cpu()
    masked_predict = inference[only_masked.unsqueeze(0)]
    masked_values = values[only_masked.unsqueeze(0)]
    predicted_vars = []
    # For now TopK=1
    k=10
    topked = masked_predict[:,0:k]
    topked_v = masked_values[:,0:k]
    for toklist,vlist in zip(topked,topked_v):
        all_p_vars=[]
        for tok,v in zip(toklist.tolist(),vlist.tolist()):
            if tok == vocab_size - 1:
                continue
            varname,varidx,var_score = idx_to_word[str(tok)],tok,v
            if len(all_p_vars)==0:
                predicted_vars.append({"pred_name":varname,"pred_idx":varidx,"confidence":var_score})
            all_p_vars.append({"pred_name":varname,"pred_idx":varidx,"confidence":var_score})
        predicted_vars[-1]["top-k"]=all_p_vars
    print("Prediction Length of each slice :",len(predicted_vars))

    type_dict = {0:'Dwarf',
                 1:'Decompiler'}
    # Var Type Inference
    inference = vartype_out.indices.cpu()
    values = vartype_out.values.cpu()
    masked_predict = inference[only_masked.unsqueeze(0)]
    masked_values = values[only_masked.unsqueeze(0)]
    k=1
    topked = masked_predict[:,0:k]
    topked_v = masked_values[:,0:k]
    predicted_vars_type = []
    for toklist,vlist in zip(topked,topked_v):
        for tok,v in zip(toklist.tolist(),vlist.tolist()):
            varname,varidx,var_score = type_dict[tok],tok,v
            predicted_vars_type.append({"variable_type":varname,"pred_idx":varidx,"confidence":var_score})
    return predicted_vars, predicted_vars_type


test_raw_code = """
__int64 __fastcall crypt_init_by_name(__int64 @@var_1@@cd@@, __int64 @@var_2@@name@@)\n{\n  return crypt_init_by_name_and_header(@@var_1@@cd@@, @@var_2@@name@@, 0LL);\n}\n
"""


def process(code: str, model, tokenizer, device):

    _code = code
    _code = _code.replace("\n"," ")
    # remove comments
    _code_lines = _code.split("\n")
    for idx, line in enumerate(_code_lines):
        if "//" in line:
            line = line[:line.index("//")]
            _code_lines[idx] = line
    _code = "\n".join(_code_lines)

    input_ids = preprocess_word_mask(_code, tokenizer)[0]
    input_ids_with_special_tokens = tokenizer.build_inputs_with_special_tokens(input_ids)
    if len(input_ids_with_special_tokens) < 800:
        # padding
        padded_input_ids = input_ids_with_special_tokens[:-1] + [1] * 800 + [2]
    else:
        padded_input_ids = input_ids_with_special_tokens
    preds = []
    preds_type = []
    n = 800
    print(f"Got {len(input_ids_with_special_tokens)} input IDs.")
    # For those functions which are greater than 800 tokens we split them into chunks of 800 and predict the vars in those chunks
    input_chunks = [padded_input_ids[i:i + n] for i in range(0, len(padded_input_ids), n)]
    for each_chunk in input_chunks:
        each_chunk_preds, each_chunk_preds_type = get_inferences(each_chunk, tokenizer, model, device)
        preds += each_chunk_preds
        preds_type += each_chunk_preds_type

    print("Length of all slices pred:",len(preds))
    print("Length of all slices pred:",len(preds_type))
    if not preds:
        return None, None
    return preds, preds_type





    
