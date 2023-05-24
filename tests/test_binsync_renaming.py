import unittest
import sys

from AVAR import VariableRenamingAPI
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


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
