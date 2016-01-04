def serialize(pointer):
    if pointer['type'] == 'static':
        return "static_" + str(pointer['value'])
    elif pointer['type'] == 'dynamic':
        return "dynamic_" + str(pointer['index']) + "_" + pointer['heap-segment']
    elif pointer['type'] == 'case-argument':
        return "case_input_" + pointer['value']
    else:
        assert False, "bad type in serialize"

def deserialize(ser):
    parts = ser.split('_', 2)
    if parts[0] == 'static':
        return {'type': 'static', 'value': int(parts[1])}
    elif parts[0] == 'dynamic':
        return {'type': 'dynamic', 'index': int(parts[1]), 'heap-segment': parts[2], 'tag': 0}
    elif parts[0] == 'case' and parts[1] == 'input':
        return {'type': 'case-argument', 'value': parts[2]}
    else:
        assert False, "bad type in deserialize"
