from AVAR.api import init_model, binsync_predict
import json
import pprint

with open('binsync_data.json', 'r') as r:
    data = json.loads(r.read())['func1']

model_interface, g_model, g_tokenizer, g_device = init_model()
og_2_pred =  binsync_predict(model_interface, g_model, g_tokenizer,
                    g_device,  data['raw_code'],   data['local_vars'], data['args'] )
pprint.pprint(og_2_pred)

# model_interface, g_model, g_tokenizer, g_device = init_model()
# def run_all_ai_commands_for_dec(self, decompilation: str, func: Function):
#     orig_name_2_popular_name = binsync_predict(self.model, self.tokenizer, self.device, decompilation, Function)