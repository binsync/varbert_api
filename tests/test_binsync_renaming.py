import unittest
import sys

from varmodel import VariableRenamingAPI
from binsync.data import Function, FunctionArgument, FunctionHeader, StackVariable


class TestBinSyncRenaming(unittest.TestCase):
    def test_renaming(self):
        api = VariableRenamingAPI(decompiler="ida")

        # testing text
        function_text = "__int64 __fastcall sub_5E007(__int64 a1, __int64 a2, const char *a3)\n{\n  __int64 v3; // rcx\n  __int64 v4; // r8\n  __int64 v5; // r9\n  unsigned int v7; // [rsp+20h] [rbp-10h]\n  int v8; // [rsp+24h] [rbp-Ch]\n  __int64 v9; // [rsp+28h] [rbp-8h]\n\n  v9 = qword_246250;\n  v7 = 0;\n  v8 = atoi(a3);\n  if ( v8 >= 0 )\n  {\n    while ( v9 )\n    {\n      *(v9 + 3240) = v8;\n      v9 = *(v9 + 21664);\n      ++v7;\n    }\n    if ( a2 )\n      sub_33178(\n        4,\n        \"WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_topic_rr'. Globalized.\\n\",\n        a1,\n        v3,\n        v4,\n        v5);\n    return v7;\n  }\n  else\n  {\n    sub_33178(4, \"WARN: [%s] 'telemetry_dump_kafka_topic_rr' has to be >= 0.\\n\", a1, v3, v4, v5);\n    return 0xFFFFFFFFLL;\n  }\n}\n// 5E064: variable 'v3' is possibly undefined\n// 5E064: variable 'v4' is possibly undefined\n// 5E064: variable 'v5' is possibly undefined\n// 246250: using guessed type __int64 qword_246250;\n"
        svar_name_data = ["v3", "v4", "v5", "v7", "v8", "v9"]
        args_name_data = ["a1", "a2", "a3"]

        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("sub_5E007", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_function = api.predict_variable_names(function_text, function)

        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]
  
        assert new_function.stack_vars[3] != function.stack_vars[3]
        assert new_function.stack_vars[4] != function.stack_vars[4]
        assert new_function.stack_vars[5] != function.stack_vars[5]
        
    def test_renaming_1(self):
        api = VariableRenamingAPI(decompiler="ida")

        # testing text
        function_text = "_int64 __fastcall main(int a1, char **a2, char **a3)\n{\n  _BOOL4 v4; // [rsp+1Ch] [rbp-24h] BYREF\n  char v5[16]; // [rsp+20h] [rbp-20h] BYREF\n  char buf[16]; // [rsp+30h] [rbp-10h] BYREF\n\n  buf[8] = 0;\n  v5[8] = 0;\n  puts(\"Username: \");\n  read(0, buf, 8uLL);\n  read(0, &v4, 1uLL);\n  puts(\"Password: \");\n  read(0, v5, 8uLL);\n  read(0, &v4, 1uLL);\n  v4 = sub_400664(buf, v5);\n  if ( !v4 )\n    sub_4006FD();\n  return sub_4006ED(buf);\n}\n"
        svar_name_data = ['v4', 'v5', 'buf']
        args_name_data = ["a1", "a2", "a3"]

        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("main", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_function = api.predict_variable_names(function_text, function)
        
        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]

        assert new_function.stack_vars[1] != function.stack_vars[1]
        assert new_function.stack_vars[2] != function.stack_vars[2]
    def test_renaming_2(self):
        api = VariableRenamingAPI(decompiler="ida")

        # testing text
        function_text = '''__int64 __fastcall main(int a1, char **a2, char **a3, char a4)
        {
        const char *v5; // rbp

        if ( a1 != 2 )
            return 0LL;
        sub_2B30(*a2);
        setlocale(6, "");
        bindtextdomain("coreutils", "/usr/share/locale");
        textdomain("coreutils");
        sub_5550(sub_2A80);
        v5 = a2[1];
        if ( !strcmp(v5, "--help") )
            sub_2700(0);
        if ( !strcmp(v5, "--version") )
            sub_4DC0(stdout, "true", &unk_6084, Version, "Jim Meyering", 0, a4);
        return 0LL;
        }
        '''
        svar_name_data = ['v5']
        args_name_data = ["a1", "a2", "a3", "a4"]
        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("main", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_function = api.predict_variable_names(function_text, function)

        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]
        assert new_function.args[3] != function.args[3]

    def test_renaming_3(self):
        api = VariableRenamingAPI(decompiler="ida")

        # testing text
        function_text =    '''  __int64 __fastcall sub_4760(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
        {
        __int128 v6[2]; // [rsp+0h] [rbp-48h] BYREF
        __m128i si128; // [rsp+20h] [rbp-28h]
        __int64 v8; // [rsp+30h] [rbp-18h]
        unsigned __int64 v9; // [rsp+38h] [rbp-10h]

        v9 = __readfsqword(0x28u);
        v6[0] = _mm_load_si128(&xmmword_A1E0);
        v8 = qword_A210;
        LODWORD(v6[0]) = 10;
        v6[1] = _mm_load_si128(&xmmword_A1F0);
        si128 = _mm_load_si128(&xmmword_A200);
        if ( !a2 || !a3 )
            abort();
        si128.m128i_i64[1] = a2;
        v8 = a3;
        return sub_3F20(a1, a4, a5, v6);
        }'''
        svar_name_data = ['v6', "s128", "v8", "v9"]
        args_name_data = ["a1", "a2", "a3", "a4", "a5"]
        # WARNING: the offsets that these stack variables have as BinSync objects are not real and are only for this testcase
        function = Function(0xdead, 0x1337, header=FunctionHeader("sub_4760", 0xdead, args={}), stack_vars={})
        for i, name in enumerate(svar_name_data):
            function.stack_vars[i] = StackVariable(i, name, None, 8, function.addr)
        for i, name in enumerate(args_name_data):
            function.args[i] = FunctionArgument(i, name, None, 8)

        new_function = api.predict_variable_names(function_text, function)

        assert new_function.args[0] != function.args[0]
        assert new_function.args[1] != function.args[1]
        assert new_function.args[2] != function.args[2]
        assert new_function.args[3] != function.args[3]
        assert new_function.args[4] != function.args[4]



if __name__ == "__main__":
    unittest.main(argv=sys.argv)
