import re
import json
import logging
from pathlib import Path

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
from libbs.plugin_installer import PluginInstaller

logger = logging.getLogger(__name__)
VAR_SIZE = 2


class VarBERTInterface:
    def __init__(self, decompiler="ghidra"):
        from varbert import SUPPORTED_MODELS, SUBSTITUTE_DECOMPILER_MODEL
        if decompiler not in SUPPORTED_MODELS:
            decompiler = SUBSTITUTE_DECOMPILER_MODEL

        self.model_base_dir = PluginInstaller.find_pkg_files("varbert") / "models" / decompiler
        if not self.model_base_dir.exists() or not self.model_base_dir.is_dir():
            raise Exception(f"Model directory {self.model_base_dir} does not exist for the decompiler "
                            f"{decompiler}. Please run `varbert install`.")

        self.out_vocab_map = self.model_base_dir / "idx_to_word.json"
        with open(self.out_vocab_map, "r") as fp:
            self.idx_to_word = json.load(fp)

        self.word_to_idx = dict((v, k) for (k, v) in self.idx_to_word.items())
        self.vocab_size = len(self.idx_to_word) + 1

        self.g_model, self.g_tokenizer, self.g_device = self.init_model()

    def init_model(self):
        g_model, g_tokenizer, g_device = self.varec_init()
        g_model.to(g_device)
        if torch.cuda.is_available():
            g_model.half()

        return g_model, g_tokenizer, g_device

    @staticmethod
    def change_case(strt):
        return ''.join(['_'+i.lower() if i.isupper()
                   else i for i in strt]).lstrip('_')

    @staticmethod
    def is_camel_case(s):
        return s != s.lower() and s != s.upper() and "_" not in s

    @staticmethod
    def normalize(k):
        if VarBERTInterface.is_camel_case(k):
            k=VarBERTInterface.change_case(k)
        else:
            k=k.lower()
        return k

    def get_var_token(self, norm_variable_word):
        token = self.word_to_idx.get(norm_variable_word,self.vocab_size-1)
        if token == self.vocab_size-1:
            if "_" in norm_variable_word:
                word_splits=norm_variable_word.split("_")
                for x in word_splits:
                    ptoken=self.word_to_idx.get(x,self.vocab_size-1)
                    if ptoken!=self.vocab_size-1:
                        token=ptoken
                        break
        return [token]

    def varec_init(self):

        if torch.cuda.is_available():
            device = torch.device("cuda")
            logger.debug("GPU found, will use GPU for inference.")
        else:
            device = torch.device("cpu")
            logger.debug("GPU not found, inference will be slower.")
        n_gpu = torch.cuda.device_count()
        config_class, model_class, tokenizer_class = MODEL_CLASSES["roberta"]

        config = config_class.from_pretrained(self.model_base_dir)
        tokenizer = tokenizer_class.from_pretrained(self.model_base_dir)
        model = model_class.from_pretrained(
            str(self.model_base_dir),
            avar_vocab_size = self.vocab_size,
            from_tf=False,
            config=config            
        )

        model.to(device)
        return model, tokenizer, device

    @staticmethod
    def create_inputs_for_model(code_txt, tokenizer):
        input_ids = tokenizer.convert_tokens_to_ids(tokenizer.tokenize(code_txt))
        input_ids = tokenizer.build_inputs_with_special_tokens(input_ids)
        return torch.tensor(input_ids, dtype=torch.long)

    @staticmethod
    def split_words(text: str):
        words = text.replace("\n", " ").split(" ")
        r = []
        for w in words:
            m = re.search(r"@@[^\s@]+@@[^\s@]+@@", w)
            if m is not None:
                if m.start() > 0:
                    r.append(w[: m.start()])
                r.append(w[m.start(): m.end()])
                if m.end() < len(w):
                    r.append(w[m.end():])
            else:
                r.append(w)
        r = [w for w in r if len(w) > 0]
        return r

    def preprocess_word_mask(self, ftext, tokenizer):
        words = VarBERTInterface.split_words(ftext)
        pwords = []
        tpwords = []
        owords = []
        towords = []
        pos = 0
        masked_pos = []
        var_words = []
        var_toks = []

        vocab = tokenizer.get_vocab()
        for word in words:
            nword = word
            if "@@" in word:
                hasbeg = False
                if word[0] != "@":
                    hasbeg = True
                splits = word.split("@@")

                variable_word = splits[-2]
                post_var = splits[-1]

                assert len(variable_word) > 0
                norm_variable_word = VarBERTInterface.normalize(variable_word)
                var_tokens = self.get_var_token(norm_variable_word)
                masked_words = ["<mask>"] * len(var_tokens)
                var_toks.append(var_tokens)
                prefix = ""
                if hasbeg:
                    prefix = splits[0]
                nword = splits[-2]
                if hasbeg:
                    nword = prefix + "@@ " + variable_word

                var_words.append(norm_variable_word)

                if hasbeg:
                    pre_toks = tokenizer.tokenize(prefix + "@@")
                    for t in pre_toks:
                        pwords.append(t)
                        owords.append(t)
                        tpwords.append(vocab[t])
                        towords.append(vocab[t])
                    pos += 1
                for ix, word in enumerate(masked_words):
                    pwords.append(word)
                    owords.append(var_tokens[ix])
                    tpwords.append(vocab[word])
                    towords.append(var_tokens[ix])
                    masked_pos.append(pos + ix)
                pos += len(var_tokens)

                if len(post_var) > 0:
                    pre_toks = tokenizer.tokenize(post_var)
                    for t in pre_toks:
                        pwords.append(t)
                        owords.append(t)
                        tpwords.append(vocab[t])
                        towords.append(vocab[t])
                    pos += 1

            else:
                toks = tokenizer.tokenize(nword)
                for t in toks:
                    pwords.append(t)
                    owords.append(t)
                    tpwords.append(vocab[t])
                    towords.append(vocab[t])
                    pos += 1
        
        assert len(tpwords) == len(towords)
        assert None not in tpwords
        assert None not in towords
        return tpwords, towords, var_words, var_toks

    def decode_toks(self, toks, tokenizer):
        words = []
        for tok in toks:
            words.append(tokenizer.decode(tok))
        decoded_str = ' '.join(words)
        return decoded_str

    def get_inferences(self, input_ids, tokenizer, model, device):
        input_ids = torch.tensor(input_ids)
        logger.debug("Input length of each slice" + str(len(input_ids)))
        only_masked = input_ids == tokenizer.mask_token_id
        outputs = model(input_ids.to(device).unsqueeze(0))
        varname_out = outputs[0]
        vartype_out = outputs[1]
        inference = varname_out.indices.cpu()
        values = varname_out.values.cpu()
        masked_predict = inference[only_masked.unsqueeze(0)]
        masked_values = values[only_masked.unsqueeze(0)]
        predicted_vars = []
        # For now TopK=1
        k = 10
        topked = masked_predict[:, 0:k]
        topked_v = masked_values[:, 0:k]
        for toklist, vlist in zip(topked, topked_v):
            all_p_vars = []
            for tok, v in zip(toklist.tolist(), vlist.tolist()):
                if tok == self.vocab_size - 1:
                    continue
                varname, varidx, var_score = self.idx_to_word[str(tok)], tok, v
                if len(all_p_vars) == 0:
                    predicted_vars.append({"pred_name": varname, "pred_idx": varidx, "confidence": var_score})
                all_p_vars.append({"pred_name": varname, "pred_idx": varidx, "confidence": var_score})
            predicted_vars[-1]["top-k"] = all_p_vars
        logger.debug("Prediction Length of each slice :" + str(len(predicted_vars)))

        type_dict = {0: 'Dwarf',
                     1: 'Decompiler'}
        # Var Type Inference
        inference = vartype_out.indices.cpu()
        values = vartype_out.values.cpu()
        masked_predict = inference[only_masked.unsqueeze(0)]
        masked_values = values[only_masked.unsqueeze(0)]
        k = 1
        topked = masked_predict[:, 0:k]
        topked_v = masked_values[:, 0:k]
        predicted_vars_type = []
        for toklist, vlist in zip(topked, topked_v):
            for tok, v in zip(toklist.tolist(), vlist.tolist()):
                varname, varidx, var_score = type_dict[tok], tok, v
                predicted_vars_type.append({"variable_type": varname, "pred_idx": varidx, "confidence": var_score})
        return predicted_vars, predicted_vars_type

    def process(self, code: str):
        model = self.g_model
        tokenizer = self.g_tokenizer
        device = self.g_device

        _code = code
        # _code = _code.replace("\n", " ")
        # # remove comments
        # _code_lines = _code.split("\n")
        # for idx, line in enumerate(_code_lines):
        #     if "//" in line:
        #         line = line[:line.index("//")]
        #         _code_lines[idx] = line
        # _code = "\n".join(_code_lines)

        input_ids = self.preprocess_word_mask(_code, tokenizer)[0]
        input_ids_with_special_tokens = tokenizer.build_inputs_with_special_tokens(input_ids)
        if len(input_ids_with_special_tokens) < 800:
            # padding
            padded_input_ids = input_ids_with_special_tokens[:-1] + [1] * 800 + [2]
        else:
            padded_input_ids = input_ids_with_special_tokens
        preds = []
        preds_type = []
        n = 800
        logger.debug(f"Got {len(input_ids_with_special_tokens)} input IDs.")
        # For those functions which are greater than 800 tokens we split them into chunks of 800 and predict the vars in those chunks
        input_chunks = [padded_input_ids[i:i + n] for i in range(0, len(padded_input_ids), n)]
        for each_chunk in input_chunks:
            each_chunk_preds, each_chunk_preds_type = self.get_inferences(each_chunk, tokenizer, model, device)
            preds += each_chunk_preds
            preds_type += each_chunk_preds_type

        logger.debug(f"Length of all slices pred: {len(preds)}")
        logger.debug(f"Length of all slices pred: {len(preds_type)}")
        if not preds:
            return None, None
        return preds, preds_type


class RobertaLMHead2(nn.Module):
    def __init__(self,config, avar_vocab_size=None):
        super().__init__()
        self.avar_vocab_size = avar_vocab_size
        self.dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.layer_norm = nn.LayerNorm(config.hidden_size, eps=config.layer_norm_eps)
        self.decoder = nn.Linear(config.hidden_size, self.avar_vocab_size, bias=False)
        self.bias = nn.Parameter(torch.zeros(self.avar_vocab_size))

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
    def __init__(self, config, avar_vocab_size=None):
        super().__init__()
        self.avar_vocab_size = avar_vocab_size
        self.dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.layer_norm = nn.LayerNorm(config.hidden_size, eps=config.layer_norm_eps)
        self.decoder = nn.Linear(config.hidden_size, VAR_SIZE, bias=False)
        self.bias = nn.Parameter(torch.zeros(VAR_SIZE))

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
    def __init__(self, config, avar_vocab_size=None):
        super().__init__(config)
        self.avar_vocab_size = avar_vocab_size
        self.lm_head2 = RobertaLMHead2(config, avar_vocab_size=avar_vocab_size)
        self.lm_head3 = RobertaLMHead3(config, avar_vocab_size=avar_vocab_size)
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
            masked_lm_loss = loss_fct(prediction_scores.view(-1, self.avar_vocab_size), masked_lm_labels.view(-1))
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

