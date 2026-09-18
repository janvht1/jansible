#!/usr/bin/python
# Purpose: filter plugin to build pp headers based on a dictionary-type input (build_pp_header, JanV)
# Author: JanV
# Change history:
#   2026/09/17 - generate a pp header from a dictionary (see example below)
#   2026/09/18 - made it more consistent to disable directives
#
# Example:
#
#    vars:
#      input_cps_header:
#        camera: "*"
#        fullscreen: "self"
#        geolocation: no   # disables the directive
#
#    {{ input_pp_header | build_pp_header }}
#
# Result:
#
#    Permissions-Policy "camera=(*), microphone=(), fullscreen=(self)"
#

from ansible import errors
from copy import deepcopy
import re

DEFAULT_PP = {
  "camera": "",
  "microphone": "",
  "geolocation": "",
  "fullscreen": "self",
  "browsing-topics": "",
  "payment": ""
}

PP_QUOTE = [
]

class FilterModule(object):
    def filters(self):
        return {
            "build_pp_header": build_pp_header,
        }

def deep_merge(defaults, override):
    if not override:
      result = deepcopy(defaults)
    else:
      result = deepcopy(defaults)
      for key, value in override.items():
          if (
              key in result
              and isinstance(result[key], dict)
              and isinstance(value, dict)
          ):
              result[key] = deep_merge(result[key], value)
          else:
              result[key] = value
    return result

def build_pp_header(input_pp_header=[], defaults=None, reportOnly=False):
    combined = deep_merge(defaults or DEFAULT_PP, input_pp_header)
    disabled_keys = { key for key, value in combined.items() if (isinstance(value,bool) and value is False) or (isinstance(value,str) and value.strip().lower() in ("false","no")) }
    unique_keys = set()
    directives = []
    for key, value in combined.items():
        directive = key
        if directive not in unique_keys and directive not in disabled_keys:
            value = "" if value is None else str(value)
            if value:
                    directives.append(f"{directive}=({value})")
            else:
                directives.append(f"{directive}=()")
                unique_keys.add(directive)
        elif directive in unique_keys and directive not in disabled_keys:
            raise errors.AnsibleFilterError('Duplicate PP header key found for: \''+ str(directive) + '\'!')
    if reportOnly:
        header = "Permissions-Policy-Report-Only"
    else:
        header = "Permissions-Policy"
    return f'{header} "{", ".join(directives)}"'
