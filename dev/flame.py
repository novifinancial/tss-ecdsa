import json
import re
def merge(blob):
    if len(blob['children']) == 0:
        return
    new_children = dict()
    for child in blob['children']:
        name = child['name']
        if name not in new_children.keys():
            new_children[name] = child
        else:
            new_children[name]['value'] += child['value']
            new_children[name]['children'] += child['children']
    new_children_list = list(new_children.values())
    blob['children'] = new_children_list
    for new_child_idx in range(len(new_children_list)):
        merge(new_children_list[new_child_idx])
    
def organize_children(blob):
    # assumes the children are all uniquely named
    parent_start = blob['start']
    last_end = parent_start
    for child_idx in range(len(blob['children'])):
        blob['children'][child_idx]['start'] = last_end
        blob['children'][child_idx]['end'] = last_end + blob['children'][child_idx]['value']
        last_end = blob['children'][child_idx]['end']
        if len(blob['children'][child_idx]['children']) > 0:
            organize_children(blob['children'][child_idx])

def parse_html():
    #d3.select("body").datum({ children:
    f = open("flame-graph.html", "r")
    text = "".join(f.readlines())
    
    jsonish_re = re.search('d3\.select\("body"\)\.datum\(\{ children: ', text)
    span = jsonish_re.span()
    head = text[0:span[1]]
    jsonish = text[span[1]:-59]
    tail = text[-59:]
    
    jsonish = jsonish.replace('name:', '"name":')
    jsonish = jsonish.replace('start:', '"start":')
    jsonish = jsonish.replace('end:', '"end":')
    jsonish = jsonish.replace('value:', '"value":')
    jsonish = jsonish.replace('children:', '"children":')
    jsonish = jsonish.replace('\n', '')
    jsonish = jsonish.replace(',}', '}')
    jsonish = jsonish.replace(',]', ']')
    
    return (head, jsonish, tail)
    
head, jsonish, tail = parse_html()
blob = dict()
blob['name'] = 'root'
blob['start'] = 0
blob['children'] = json.loads(jsonish)
merge(blob)
organize_children(blob)

f = open("flame-graph-new.html", "w")
f.write(head)
f.write(str(blob['children']))
f.write(tail)