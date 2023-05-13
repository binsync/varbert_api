# VarBERT
Predict variable names for your favorite decompiler. 

Model available for IDA. Ghidra coming soon!

# Setup
```
 mkdir -p varbert/models
 Download and copy models to `varbert/models`
 pip install -r requirements.txt
```

# Usage
```
python run_inference.py --decompiler=<decompiler_name> --all
decompiler_name: ida/IDA, ghidra/Ghidra
all: To predict variable names for both source code variables and decompiler-generated variable names. (Default False) 
```

# Example
## Input 
```
{funcname: {raw_code: '', 'local_vars: [], 'args': []}}
for now: (binsync_data.json)
```
## Output 
### `python run_inference.py --decompiler=ida --all`
```
original: predicted

{'a1': 'filename',
 'a2': 'name',
 'a3': 'value_ptr',
 'v3': 'list /*decompiler*/',
 'v4': 'changes /*decompiler*/',
 'v5': 'plugins_list /*decompiler*/',
 'v7': 'size',
 'v8': 'value',
 'v9': 'table'}
```

### `python run_inference.py --decompiler=ida`
```
original: predicted

{'a1': 'filename',
 'a2': 'name',
 'a3': 'value_ptr',
 'v3': 'v3 /*decompiler*/',
 'v4': 'v4 /*decompiler*/',
 'v5': 'v5 /*decompiler*/',
 'v7': 'size',
 'v8': 'value',
 'v9': 'table'}
```


