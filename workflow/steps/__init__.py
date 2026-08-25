"""The sealing sequence.

Each step chooses modules from enclavize.aws and orders them. There is no AWS
usage of its own to get wrong here, which is why steps are covered by offline
ordering tests rather than real-account ones.
"""
