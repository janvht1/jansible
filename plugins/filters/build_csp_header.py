#!/usr/bin/python
# Purpose: filter plugin to build csp headers based on a dictionary-type input (build_csp_header, JanV)
# Author: JanV
# Change history:
#   2026/08/26 - generate a csp header from a dictionary (see example below)
#   2026/08/26 - added a ReportOnly option
#   2026/09/11 - throw an error when duplicate CSP keys are found
#   2026/09/11 - added the option to disable a default directive
#   2026/09/17 - catched undefined override condition
#   2026/09/18 - made it more consistent to disable directives
#
# Example:
#
#    vars:
#      input_csp_header:
#        connect_src: "self https://*.example.com"
#        frame_ancestors: "none"
#        upgrade_insecure_requests: no   # disables the directive
#        block_all_mixed_content:
#
#    {{ input_csp_header | build_csp_header }}
#
# Result:
#
#    Content-Security-Policy "base-uri 'self'; default-src 'self'; connect-src 'self' https://*.example.com; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; img-src 'self' data: https://images.example.com; font-src 'self' data:; frame-src 'self'; frame-ancestors 'none'; form-action 'self'; block-all-mixed-content;
#

from ansible import errors
from copy import deepcopy
import re

DEFAULT_CSP = {
  "base_uri": "self",
  "default_src": "self",
  "connect_src": "self",
  "script_src": "self",
  "style_src": "self https://fonts.googleapis.com",
  "font_src": "self data: https://fonts.gstatic.com",
  "img_src": "self data:",
  "object_src": "none",
  "frame_src": "self",
  "frame_ancestors": "self",
  "form_action": "self",
  "upgrade_insecure_requests": None
}

CSP_QUOTE = [
    "self",
    "none",
    "unsafe-inline",
    "unsafe-eval",
    "strict-dynamic",
    "report-sample",
]

class FilterModule(object):
    def filters(self):
        return {
            "build_csp_header": build_csp_header,
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

def build_csp_header(input_csp_header=[], defaults=None, reportOnly=False):
    combined = deep_merge(defaults or DEFAULT_CSP, input_csp_header)
    disabled_keys = { key.replace("_", "-") for key, value in combined.items() if (isinstance(value,bool) and value is False) or (isinstance(value,str) and value.strip().lower() in ("false","no")) }
    unique_keys = set()
    directives = []
    quote_regex = re.compile(r"(" + "|".join(map(re.escape, CSP_QUOTE)) + r")")
    for key, value in combined.items():
        directive = key.replace("_", "-")
        if directive not in unique_keys and directive not in disabled_keys:
            value = "" if value is None else str(value)
            value = quote_regex.sub(r"'\1'", value)
            if value:
                    directives.append(f"{directive} {value}")
            else:
                directives.append(directive)
                unique_keys.add(directive)
        elif directive in unique_keys and directive not in disabled_keys:
            raise errors.AnsibleFilterError('Duplicate CSP header key found for: \''+ str(directive) + '\'!')
    if reportOnly:
        header = "Content-Security-Policy-Report-Only"
    else:
        header = "Content-Security-Policy"
    return f'{header} "{"; ".join(directives)};"'
