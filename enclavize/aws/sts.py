"""Who are we."""


def account_id(sts) -> str:
    return sts.get_caller_identity()["Account"]
