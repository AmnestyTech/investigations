# Android FinFisher 2019 obfuscated strings extraction from decompiled Java code using Procyon
# Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)
#
# Parse Java source files of FinSpy weaponized APK

import javalang
import pystache
import glob
import sys
from javalang.tree import StatementExpression, MethodInvocation


def extract_obfuscated_strings(method):
    obfuscated_strings = []
    for statement in method.body:
        acc = []
        if type(statement) is not StatementExpression:
            continue
        if type(statement.expression) is not MethodInvocation:
            continue
        if statement.expression.member == 'add' and statement.expression.qualifier == 'list':
            for child in statement.expression.arguments[0].initializer.children:
                for literal in child:
                    acc.append(int(literal.value))
        obfuscated_strings.append(acc)

    return obfuscated_strings


def parse_source_code(source_dir, method_name='OOOoOoiIoIIiO0o01I1I00'):
    data = []
    java_files = glob.glob(f'{source_dir}/**/*.java', recursive=True)
    for java_file in java_files:
        with open(java_file) as java:
            java_code = java.read()
            try:
                tree = javalang.parse.parse(java_code)
                for type in tree.types:
                    if not type.methods:
                        continue
                    for method in type.methods:
                        if method_name in method.name:
                            # print(f'{tree.package.name}.{type.name}.{method.name}')
                            data.append({
                                'class_name': f'{tree.package.name}.{type.name}',
                                'strings': extract_obfuscated_strings(method)
                            })
            except Exception as e:
                print(java_file)
                print(e)
    return data


def generate_python_db(data, output='encoded_strings.py'):
    with open('strings_db.tpl') as tpl_file:
        tpl = tpl_file.read()
    with open(output, mode='w') as output_file:
        output_file.write(pystache.render(tpl, {'data': data}))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'Usage: python {sys.argv[0]} <Java sources directory>')
        sys.exit(1)

    source_dir = str(sys.argv[1])
    data = parse_source_code(source_dir)
    generate_python_db(data)
