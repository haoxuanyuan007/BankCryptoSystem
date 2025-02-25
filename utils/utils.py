def mask_account_number(account_number: str) -> str:
    """
    Only show last 4 digits at front end for security reasons.
    """
    if len(account_number) >= 4:
        return "****" + account_number[-4:]
    return account_number