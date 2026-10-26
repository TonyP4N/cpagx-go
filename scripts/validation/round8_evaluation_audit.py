"""Bounded reproduction of old reference coupling; does not import old runtime."""
import ast
import json
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
def main():
    path=REPO/'tests/evaluation_final.py'
    tree=ast.parse(path.read_text())
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='derive_gold_units')
    node.returns=None
    for arg in node.args.args:arg.annotation=None
    module=ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[]))
    namespace={'extract_attack_info':lambda _: {}}
    exec(compile(module,str(path),'exec'),namespace)
    sample={'id':'synthetic_predicted_unit','category':'attack_impact','evidence':{}}
    before=namespace['derive_gold_units'](None,[])
    after=namespace['derive_gold_units'](None,[sample])
    assert before==[] and after==[sample]
    print(json.dumps({'source':'tests/evaluation_final.py','function':'derive_gold_units','line':node.lineno,'empty_predictions_gold':before,'added_prediction_gold':after,'prediction_changes_reference':True,'decision':'not admitted as independent gold for P3','scope':'function-level synthetic reproduction; no old service execution'}))
if __name__=='__main__':main()
