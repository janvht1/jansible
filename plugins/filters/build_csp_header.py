#!/usr/bin/python
# Purpose: filter plugin to build csp headers based on a dictionary-type input (build_csp_header, JanV)
# Author: JanV
# Change history:
#   2026/08/26 - generate a csp header from a dictionary (see example below)
#   2026/08/26 - added ReportOnly option
#
# Example:
#
#    vars:
#      input_csp_header:
#        connect_src: "self https://*.example.com"
#        frame_ancestors: "none"
#        upgrade-insecure-requests:
#
#    {{ input_csp_header | build_csp_header }}
#
# Result:
#
#    Content-Security-Policy "base-uri 'self'; default-src 'self'; connect-src 'self' https://*.example.com; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; img-src 'self' data: https://images.example.com; font-src 'self' data:; frame-src 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests;"
#

from ansible import errors
from copy import deepcopy
import re

DEFAULT_CSP = {
  "base_uri": "self",
  "default_src": "self",
  "connect_src": "self",
  "script_src": "self",
  "style_src": "self unsafe-inline",
  "object_src": "none",
  "img_src": "self data:",
  "font_src": "self data:",
  "frame_src": "self",
  "frame_ancestors": "self",
  "form_action": "self"
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

def build_csp_header(input_csp_header, defaults=None, reportOnly=False):
    combined = deep_merge(defaults or DEFAULT_CSP, input_csp_header)
    directives = []
    quote_regex = re.compile(r"(" + "|".join(map(re.escape, CSP_QUOTE)) + r")")
    for key, value in combined.items():
        directive = key.replace("_", "-")
        value = "" if value is None else str(value)
        value = quote_regex.sub(r"'\1'", value)
        if value:
            directives.append(f"{directive} {value}")
        else:
            directives.append(directive)
    if reportOnly:
        header = "Content-Security-Policy-Report-Only"
    else:
        header = "Content-Security-Policy"
    return f'{header} "{"; ".join(directives)};"'
