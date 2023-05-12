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
python run.py --decompiler=<decompiler_name>
decompiler_name: ida/IDA, ghidra/Ghidra
```
