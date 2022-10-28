# flame.py: a script to reorganize flame-graph.html
# Running this script while a copy of flame-graph.html is found in the same directory
# will produce a new file called flame-graph-new.html in which all invocations of the
# same subfunction within a given function are grouped together.
#
# Context: The "flame" rust crate produces flame graphs which can help visualize which
# parts of the program require the most time to execute. This flamegraph orders functions 
# chronologically on the x axis, but if the same function is called in multiple places in 
# the general execution flow, then it will appear broken up into various chunks, making 
# it hard to tell how much of the overall execution is attributable to that function.
#
# This code essentially parses the json in the flame-graph.html file output by the flame 
# crate, reorganizes it, and writes a new html flame graph which groups together invocations
# in a more convenient way.


import json
import re

# Merges any separate timings of the same function with the same parent together.
# For example, if function A() calls C() twice and function B() calls C() four times,
# this would show A() and C() both calling B() once, but it taking around twice as long in C()
# (assuming in this example that all calls to C() take roughly the same amount of time).
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

# Aligns a function's subfunctions (children) to all be positioned sequentially along the x axis
# and start at the same time as their parent.
def organize_children(blob):
    parent_start = blob['start']
    last_end = parent_start
    for child_idx in range(len(blob['children'])):
        blob['children'][child_idx]['start'] = last_end
        blob['children'][child_idx]['end'] = last_end + blob['children'][child_idx]['value']
        last_end = blob['children'][child_idx]['end']
        if len(blob['children'][child_idx]['children']) > 0:
            organize_children(blob['children'][child_idx])

# flame-graph.html is composed of a large json data blob and some code to process and display it.
# This parses out the json part specifically and formats it in a way the python json module can handle.
def parse_html():
    f = open("flame-graph.html", "r")
    text = "".join(f.readlines())
    
    # search the file for the specific substring d3.select("body").datum({ children:
    # everthing between this substring and the last 59 characters of the file is json data
    jsonish_re = re.search('d3\.select\("body"\)\.datum\(\{ children: ', text)
    span = jsonish_re.span()
    head = text[0:span[1]]
    jsonish = text[span[1]:-59]
    tail = text[-59:]
    
    # the "json-ish" text from the html file needs to be modified slightly so that
    # the python json parser can handle it
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