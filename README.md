# VarBERT API
The VarBERT API is a Python library to access and use the latest models from the S&P 2024 work 
[""Len or index or count, anything but v1": Predicting Variable Names in Decompilation Output with Transfer Learning"](https://www.atipriya.com/files/papers/varbert_oakland24.pdf), featuring VarBERT. 
VarBERT is a BERT-based model that predicts variable names for decompiled code.
To train new models and understand the pipeline, see the [VarBERT paper repo](https://github.com/sefcom/VarBERT).
Specialized models exist for IDA Pro and Ghidra, but can be used on any decompiler. 

<p align="center">
    <img src="./assets/varbert_no_background.png" style="width: 50%;" alt="DAILA context menu"/>
</p>

The main focus of this project is to provide an library API and CLI access to VarBERT models, but, it has 
been designed to be used in decompiler directly using the [DAILA](https://github.com/mahaloz/DAILA) project. 
DAILA comes with the VarBERT API bundled, so you do not need to install VarBERT if you are using DAILA.

## Install 
```
pip3 install varbert && varbert --download-models
```

This will install the VarBERT API library and download the models to be stored inside the VarBERT package.
You can optionally provide a decompiler name to `--download-models` to only download the models for that decompiler.

## Usage
The VarBERT API can be used in three ways:
- From the CLI, directly on decompiled text (without an attached decompiler)
- As a scripting library 
- As a decompiler plugin (using [DALIA](https://github.com/mahaloz/DAILA)) 

### Command Line (without running a decompiler)
Note that VarBERT runs better when it is directly hooked up to a decompiler because it can use additional semantic information that the decompiler knows about the decompiled code.
However, we do have the ability to run VarBERT without a running decompiler, only operating on the text from the command line.

Running the following will cause VarBERT to read a function from standard input and output the function with predicted variable names to standard out:
```bash
varbert --predict --decompiler ida
```

You can select different decompilers that will use different models that are trained on the different decompilers.
If you do not specify a decompiler, the default is IDA Pro.
As an example, you can also give no decompiler:
```bash 
 echo "__int64 sub_400664(char *a1,char *a2)\n {}" | varbert -p
```

### Scripting
#### Without Decompiler
```python
from varbert import VariableRenamingAPI
api = VariableRenamingAPI(decompiler_name="ida", use_decompiler=False)
new_names, new_code = api.predict_variable_names(decompilation_text="__int64 sub_400664(char *a1,char *a2)\n {}", use_decompiler=False)
print(new_code)
```

You can also find more examples in the [tests.py](./tests/tests.py) file.

#### Inside Decompiler
You can use VarBERT as a scripting library inside your decompiler, utilizing LibBS.
```python
from varbert import VariableRenamingAPI
from libbs.api import DecompilerInterface
dec = DecompilerInterface()
api = VariableRenamingAPI(decompiler_interface=dec)
for func_addr in dec.functions:
    new_names, new_code = api.predict_variable_names(function=dec.functions[func_addr])
    print(new_names)
```

### As a Decompiler Plugin
If you would like to use VarBERT as a decompiler plugin, you can use [DAILA](https://github.com/mahaloz/DAILA).
You should follow the instructions on the DAILA repo to install DAILA, but it's generally as simple as:
```bash
pip3 install dailalib && daila --install
```

You can find a demo of VarBERT running inside DAILA below:

[![VarBERT Demo](https://img.youtube.com/vi/nUazQm8sFL8/0.jpg)](https://youtu.be/nUazQm8sFL8 "DAILA v2.1.4: Renaming variables with local VarBERT model")

## Citing 
If you use VarBERT in your research, please cite our paper:
```
TODO
```
